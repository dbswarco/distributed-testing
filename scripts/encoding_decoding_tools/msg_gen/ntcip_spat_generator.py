#!/usr/bin/env python3
import time
import json
import socket
import os
import argparse
from argparse import RawTextHelpFormatter
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
import logging
from datetime import datetime, timezone

import j2735_202409

try:
    # Python 3.11+
    from enum import StrEnum
except ImportError:
    import enum
    class StrEnum(str, enum.Enum):
        def __new__(cls, value):
            # Create a str, and attach it as the Enum value
            obj = str.__new__(cls, value)
            obj._value_ = value
            return obj
        def __str__(self):
            return str(self.value)
        def __repr__(self):
            return f"{self.value}"

MessageFrame = j2735_202409.MessageFrame.MessageFrame

module_logger = logging.getLogger('main.snmp_getsetter')

# function time debugging ---

import time
from functools import wraps

def timed(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        t0 = time.perf_counter_ns()
        try:
            return await func(*args, **kwargs)
        finally:
            dt_ns = time.perf_counter_ns() - t0
            dt_s = dt_ns / 1_000_000_000
            print(f"{func.__name__} took {dt_s:.6f}s ({dt_ns/1_000_000:.3f} ms)")
    return wrapper


class NTCIP1202:
    class Phase:
        class Timing(StrEnum):
            MinimumGreen = '1.3.6.1.4.1.1206.4.2.1.1.2.1.4'
            Maximum1 = '1.3.6.1.4.1.1206.4.2.1.1.2.1.6'
            YellowChange = '1.3.6.1.4.1.1206.4.2.1.1.2.1.8'
            RedClear = '1.3.6.1.4.1.1206.4.2.1.1.2.1.9'
        class StatusGroup(StrEnum):
            Greens = '1.3.6.1.4.1.1206.4.2.1.1.4.1.4'
            Yellows = '1.3.6.1.4.1.1206.4.2.1.1.4.1.3'
            Reds = '1.3.6.1.4.1.1206.4.2.1.1.4.1.2'
            Walks = '1.3.6.1.4.1.1206.4.2.1.1.4.1.7'
            PedClears = '1.3.6.1.4.1.1206.4.2.1.1.4.1.6'
            DontWalks = '1.3.6.1.4.1.1206.4.2.1.1.4.1.5'
    class Coord:
        class Split(StrEnum):
            Time = '1.3.6.1.4.1.1206.4.2.1.4.9.1.3'
        class Pattern(StrEnum):
            Status = '1.3.6.1.4.1.1206.4.2.1.4.10'
    class Controller(StrEnum):
        LocalTime = '1.3.6.1.4.1.1206.4.2.6.3.6'
        StandardTimeZone = '1.3.6.1.4.1.1206.4.2.6.3.5'
        GlobalTime = '1.3.6.1.4.1.1206.4.2.6.3.1'

class McCain:
    class DetectorControlState(StrEnum):
        Vehicle = '1.3.6.1.4.1.1206.3.21.2.13.4.1.1'
        Pedestrian = '1.3.6.1.4.1.1206.3.21.2.14.4.1.1'

class SnmpGetError(Exception):
    """Custom exception to signal SNMP GET failures."""
    pass


def get_oid(member, *indexes) -> str:
    parts = [str(member), *(str(i) for i in indexes if i is not None and i != '')]
    return ".".join(parts)


async def send_snmp_set_command(ip, community, oid, value, port):
    snmp_engine = SnmpEngine()
    try:
        error_indication, error_status, error_index, var_binds = await set_cmd(
            snmp_engine,
            CommunityData(community, mpModel=0),
            await UdpTransportTarget.create((ip, port)),
            ContextData(),
            ObjectType(ObjectIdentity(tuple(map(int, oid.split('.')))), value)
        )
        module_logger.debug(f"send_snmp_set_command: {error_indication}, {error_status}, {error_index}, {var_binds}")

        if error_indication:
            msg = f"{ip}: SNMP GET {oid} transport error: {error_indication}"
            module_logger.error(msg)
            raise SnmpGetError(msg)

        elif error_status:
            bad_var = (
                var_binds[int(error_index) - 1][0] if error_index else "unknown"
            )
            msg = (f"{ip}: SNMP GET {oid} agent error: "
                   f"{error_status.prettyPrint()} at {bad_var}")
            module_logger.error(msg)
            raise SnmpGetError(msg)

        value = var_binds[0][1]  # PySNMP type (e.g., Integer, OctetString)
        module_logger.debug(f"{ip}: SET {oid} {value.prettyPrint()}")
        return [ip, oid, value]

    finally:
        snmp_engine.close_dispatcher()
        await asyncio.sleep(0.1)


async def send_snmp_get_command(ip, community, oid, port):
    snmp_engine = SnmpEngine()
    try:
        iterator = get_cmd(
            snmp_engine,
            CommunityData(community, mpModel=0),
            await UdpTransportTarget.create((ip, port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        error_indication, error_status, error_index, var_binds = await iterator

        if error_indication:
            msg = f"{ip}: SNMP GET {oid} transport error: {error_indication}"
            module_logger.error(msg)
            raise SnmpGetError(msg)

        if error_status:
            bad_var = (
                var_binds[int(error_index) - 1][0] if error_index else "unknown"
            )
            msg = (f"{ip}: SNMP GET {oid} agent error: "
                   f"{error_status.prettyPrint()} at {bad_var}")
            module_logger.error(msg)
            raise SnmpGetError(msg)

        value = var_binds[0][1]  # PySNMP type (e.g., Integer, OctetString)
        module_logger.debug(f"{ip}: GET {oid} -> {value.prettyPrint()}")
        return [ip, oid, value]

    finally:
        snmp_engine.close_dispatcher()
        await asyncio.sleep(0.1)


async def get_int(ip: str, community: str, oid: str, port: int) -> int:
    try:
        res = await send_snmp_get_command(ip, community, oid, port)
        if res is None:
            msg = f"{ip}: SNMP GET {oid} agent error: no value returned"
            raise SnmpGetError(msg)
        val = res[2]
        # Handle PySNMP types or plain Python types
        if hasattr(val, "prettyPrint"):
            val = val.prettyPrint()
        return int(val)  # works for int-ish strings as well
    except Exception as e:
        raise e


@timed
async def get_phase_j2735_states_ntcip(ip: str, community: str, sig_grps: list, port: int) -> dict:

    def bits_lsb_first(byte_val: int) -> list[int]:
        # Return 8 bits least-significant-bit first: bit 0 -> phase 1 (or 9), bit 7 -> phase 8 (or 16)
        return [(byte_val >> i) & 1 for i in range(8)]

    if any(v > 8 for v in sig_grps):
        # Index 1: phases 1..8, Index 2: phases 9..16
        g1, g2, y1, y2, r1, r2 = await asyncio.gather(
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Greens, '1'), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Greens, '2'), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Yellows, '1'), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Yellows, '2'), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Reds, '1'), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Reds, '2'), port),
        )

        # Build per-phase bit arrays for phases 1..16 (not strings)
        g_bits = bits_lsb_first(g1) + bits_lsb_first(g2)  # [phase1..phase16]
        y_bits = bits_lsb_first(y1) + bits_lsb_first(y2)
        r_bits = bits_lsb_first(r1) + bits_lsb_first(r2)

    else:
        # Index 1: phases 1..8
        g1, y1, r1 = await asyncio.gather(
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Greens, '1'), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Yellows, '1'), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.StatusGroup.Reds, '1'), port),
        )

        # Build per-phase bit arrays for phases 1..8 (not strings)
        g_bits = bits_lsb_first(g1)  # [phase1..phase8]
        y_bits = bits_lsb_first(y1)
        r_bits = bits_lsb_first(r1)

    states = {}
    for sg in sig_grps:
        i = sg - 1  # 0-based index
        if r_bits[i]:
            states[sg] = "stop-And-Remain"
        elif y_bits[i]:
            states[sg] = "protected-clearance"
        elif g_bits[i]:
            states[sg] = "protected-Movement-Allowed"
        else:
            continue

    return states


@timed
async def get_phase_j2735_times_ntcip(ip: str, community: str, sig_grps: list, port: int):
    time_to_change = {}
    controller_gmt_epoch = 0

    for sg in sig_grps:
        ptn = await get_int(ip, community, get_oid(NTCIP1202.Coord.Pattern.Status), port)
        controller_localtz_epoch, tz_differential, min_grn, split, yellow, red = await asyncio.gather(
            get_int(ip, community, get_oid(NTCIP1202.Controller.LocalTime), port),
            get_int(ip, community, get_oid(NTCIP1202.Controller.StandardTimeZone), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.Timing.MinimumGreen, sg), port),
            get_int(ip, community, get_oid(NTCIP1202.Coord.Split.Time, ptn, sg), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.Timing.YellowChange, sg), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.Timing.RedClear, sg), port)
        )
        controller_gmt_epoch = (controller_localtz_epoch - tz_differential) * 10
        time_to_change[sg] = {'min': int(controller_gmt_epoch + min_grn),
                              'max': int(controller_gmt_epoch + split - (yellow / 10) - (red / 10))}

    return [controller_gmt_epoch, time_to_change]


@timed
async def get_signal_state(ip, community, int_id, sig_grps):
    sg_states, sg_ttc = await asyncio.gather(
        get_phase_j2735_states_ntcip(ip, community, sig_grps, 10000 + int_id),
        get_phase_j2735_times_ntcip(ip, community, sig_grps, 10000 + int_id),
    )

    states = []
    for sg, event_state in sg_states.items():
        states.append(
            {
            "signalGroup": sg,
            "state-time-speed": [
                {
                    "eventState": event_state,
                    "timing": {
                        # Both are INTEGER TimeMark values
                        "minEndTime": sg_ttc[1].get(sg).get('min'),
                        "maxEndTime": sg_ttc[1].get(sg).get('max'),
                    },
                }
            ],
        }
        )

    return sg_ttc[0], states


def compute_moy_and_time_mark():
    """
    Compute:
      - Minute of year (moy)
      - TimeMark in 0.1s units from the top of the current UTC hour (0..35999)
    """
    now = datetime.now(timezone.utc)

    # Minute of year (unchanged)
    moy = ((now.timetuple().tm_yday - 1) * 24 * 60) + now.hour * 60 + now.minute

    # Seconds since top of the hour
    seconds_since_hour = now.minute * 60 + now.second
    ms_since_hour = seconds_since_hour * 1000 + now.microsecond // 1000

    # TimeMark: 0.1 s units from top of the current hour, should be 0..35999
    time_mark = ms_since_hour // 100
    if time_mark > 35999:
        # Should not normally happen, but be safe
        time_mark = 35999

    return moy, int(time_mark)


@timed
async def build_spat_for_intersection(
    intersection_id,
    intersection_ip,
    moy,
    signal_groups
):
    """
    Build a SPaT JER dict for a single intersection, given existing timing/state info.
    """

    states = await get_signal_state(intersection_ip, 'public', intersection_id, signal_groups)

    ### this gets time from the local clock, if you want to get time from the controller, 
    #   you will need to change the time stamps here to get from NTCIP 

    spat = {
        "messageId": 19,
        "value": {
            "timeStamp": states[0],  # DSecond-ish; still 0.1s from hour, but valid INTEGER
            "intersections": [
                {
                    "id": {"id": int(intersection_id)},
                    "revision": 0,
                    "status": "0000",
                    "moy": int(moy),
                    "timeStamp": states[0],
                    "states": states[1],
                }
            ],
        },
    }

    return spat


def encode_spat_to_uper_hex(spat_dict):
    jer_str = json.dumps(spat_dict, separators=(",", ":"))
    msg = MessageFrame
    msg.from_jer(jer_str)
    uper_bytes = msg.to_uper()
    return uper_bytes.hex()


def build_active_message(hex_payload):
    """
    Build Active Message Format (AMF) text with the given hex payload.
    """
    return (
        "Version=0.7\n"
        "Type=SPAT\n"
        "PSID=0x8003\n"
        "Priority=7\n"
        "TxMode=CONT\n"
        "TxChannel=183\n"
        "TxInterval=0\n"
        "DeliveryStart=\n"
        "DeliveryStop=\n"
        "Signature=True\n"
        "Encryption=False\n"
        f"Payload={hex_payload}\n"
    )


def print_frame_log(intersection_id, debug_info, hex_str):
    print(
        f"[SPaT] Int {intersection_id} | "
        f"{debug_info['timestamp']} | "
        f"Signal groups={debug_info['signal_groups']}\n"
        f"   HEX: {hex_str}\n"
    )


def load_phase_config(path):
    """
    Load phase group configuration from JSON.

    Expected JSON format:
      {
        "intersections": [
          {"id": 100, "signal_groups": [10,12,14],"ip": "1.2.3.4"},
          {"id": 101, "signal_groups": [2,6,8],"ip": "1.2.3.5"}
        ]
      }
    """
    if not path:
        raise ValueError("A config file is required; provide --config <path>")

    path = os.path.expanduser(path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    intersections = []

    if isinstance(data, dict):
        if "intersections" in data and isinstance(data["intersections"], list):
            for item in data["intersections"]:
                if not isinstance(item, dict) or "id" not in item:
                    continue
                signal_groups = item.get("signal_groups")
                if not signal_groups:
                    raise ValueError(f"Intersection {item.get('id')} missing signal_groups")
                intersections.append(
                    {
                        "id": int(item["id"]),
                        "signal_groups": signal_groups,
                        "ip": item.get("ip"),
                    }
                )

    if not intersections:
        raise ValueError("No intersections defined in config; each needs signal_groups")

    return intersections


async def main():
    parser = argparse.ArgumentParser(
        formatter_class=RawTextHelpFormatter, description=(
            "Generate SPaT using signal group states polled from an NTCIP TSC and send as "
            "Active Message Format over UDP.\n\n"
            "Run outside the container (requires Python 3.8+ for j2735):\n"
            "  1) Install deps from this folder: ./install_dependencies.sh\n"
            "  2) Provide a config JSON with intersections, controller IPs, and signal_groups.\n\n"
            "Adapter Configuration:\n"
            "  - To publish encoded J2735 hex over TENA V2X Messages: \n"
            "    - Set VUG_DOCKER_START_V2X_ADAPTER=true in your site config \n"
            "    - Match IP/port with adapter: VUG_V2X_ADAPTER_RECEIVE_ADDRESS should equal --ip and \n"
            "      VUG_V2X_ADAPTER_RECEIVE_PORT should equal --port - you can pass them directly: \n"
            "        --ip $VUG_V2X_ADAPTER_RECEIVE_ADDRESS --port $VUG_V2X_ADAPTER_RECEIVE_PORT\n\n"
            "  - To convert the TENA V2X Messages into Traffic Signal Controller data for visualization: \n"
            "    - Set VUG_DOCKER_START_ENTITY_GENERATOR=true \n"
            "    - Ensure every intersection ID you send exists in the scenario XML under \n"
            "      intersectionSignalControllers and phaseSignalMappings\n\n"
            "Examples:\n"
            "  - Config-driven intersections to a local receiver:\n"
            "      ./ntcip_spat_generator.py --config ./ntcip_spat_config.json --ip 127.0.0.1 --port 1516\n\n"
            "  - Multiple intersections with slower rate (IDs/signal_groups come from config):\n"
            "      ./ntcip_spat_generator.py --config ./ntcip_spat_config.json --hz 5\n\n"
            "Press Ctrl+C to stop the generator."
        )
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print raw SPaT JER payloads before encoding",
    )

    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help=(
            "Path to JSON config with per-intersection signal_groups. "
            "Intersections emitted are derived from the config; no default intersection IDs."
        ),
    )

    parser.add_argument(
        "--hz",
        type=float,
        default=10.0,
        help="Output rate in Hz for all intersections (default: 10.0)",
    )

    # UDP target
    parser.add_argument(
        "--ip",
        type=str,
        default="127.0.0.1",
        help="Destination IP for Active Message Format UDP (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=56700,
        help="Destination UDP port for Active Message Format (default: 56700)",
    )

    args = parser.parse_args()


    interval = 1.0 / args.hz

    intersections = load_phase_config(args.config)

    # UDP socket
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = (args.ip, args.port)

    print("Press Ctrl+C to stop\n")
    print(
        f"Intersections: {[i['id'] for i in intersections]} | "
        f"Rate: {args.hz} Hz | "
        f"UDP target: {args.ip}:{args.port}\n"
    )

    try:
        # Sync controller clocks with PC since virtual controllers run slow over time
        for intersection in intersections:
            intersection_id = intersection["id"]
            intersection_ip = intersection.get("ip")
            current_datetime = int(datetime.now().timestamp())
            await send_snmp_set_command(intersection_ip, 'administrator',
                                              NTCIP1202.Controller.GlobalTime, Counter32(current_datetime),
                                              intersection_id + 10000)

        while True:
            loop_start = time.time()

            # Compute controller state ONCE per tick
            moy, time_mark = compute_moy_and_time_mark()

            debug_info = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            }

            # Build, encode, log, and send for each intersection
            for intersection in intersections:
                intersection_id = intersection["id"]
                signal_groups = intersection["signal_groups"]
                intersection_ip = intersection.get("ip")
                debug_info["signal_groups"] = signal_groups

                spat_jer = await build_spat_for_intersection(
                    intersection_id,
                    intersection_ip,
                    moy,
                    signal_groups
                )
                if args.verbose:
                    print(f"spat_jer: {spat_jer}")
                hex_str = encode_spat_to_uper_hex(spat_jer)

                # Human-readable log
                print_frame_log(intersection_id, debug_info, hex_str)

                # Build AMF text and send via UDP
                amf_text = build_active_message(hex_str)
                sk.sendto(amf_text.encode("ascii"), target)

            # Rate control
            sleep_time = interval - (time.time() - loop_start)
            if sleep_time > 0:
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\nStopped SPaT generator.")


if __name__ == "__main__":
    asyncio.run(main())
