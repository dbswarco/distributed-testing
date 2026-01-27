#!/usr/bin/env python3
import time
import json
import socket
import os
import argparse
from argparse import RawTextHelpFormatter
import asyncio
import logging
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Dict, Tuple


import j2735_202409
from ntcip_snmp_utils import NTCIP1202, send_snmp_set_command, get_int, get_oid, Counter32

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


@dataclass
class PhaseTimingCacheEntry:
    min_grn: int
    max_grn: int
    yellow: int
    red: int

# Keyed by (ip, port, sg)
_phase_timing_cache: Dict[Tuple[str, int, int], PhaseTimingCacheEntry] = {}
_phase_timing_locks: Dict[Tuple[str, int, int], asyncio.Lock] = {}

# ----- CACHE HELPERS -----

async def _ensure_phase_timing_cached(ip: str, community: str, port: int, sg: int) -> PhaseTimingCacheEntry:
    """
    Fetch and cache min_grn, max_grn, yellow, red for (ip, port, sg) once.
    Returns a PhaseTimingCacheEntry with raw SNMP integer values.
    """
    key = (ip, port, sg)
    if key in _phase_timing_cache:
        return _phase_timing_cache[key]

    lock = _phase_timing_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _phase_timing_locks[key] = lock

    async with lock:
        if key in _phase_timing_cache:
            return _phase_timing_cache[key]

        min_grn, max_grn, yellow, red = await asyncio.gather(
            get_int(ip, community, get_oid(NTCIP1202.Phase.Timing.MinimumGreen, sg), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.Timing.Maximum1, sg), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.Timing.YellowChange, sg), port),
            get_int(ip, community, get_oid(NTCIP1202.Phase.Timing.RedClear, sg), port),
        )

        entry = PhaseTimingCacheEntry(
            min_grn=int(min_grn),
            max_grn=int(max_grn),
            yellow=int(yellow),
            red=int(red),
        )
        _phase_timing_cache[key] = entry
        return entry


def clear_phase_timing_cache(ip: str, port: int, sg: int) -> None:
    """Clear all cache or targeted entries."""
    if ip is None and port is None and sg is None:
        _phase_timing_cache.clear()
        _phase_timing_locks.clear()
        return

    # Selective clear
    to_delete = []
    for key in _phase_timing_cache.keys():
        kip, kport, ksg = key
        if (ip is None or ip == kip) and (port is None or port == kport) and (sg is None or sg == ksg):
            to_delete.append(key)
    for key in to_delete:
        _phase_timing_cache.pop(key, None)
        _phase_timing_locks.pop(key, None)


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

    # Calculate epoch deciseconds for Jan 1, 00:00 UTC of current year
    current_year_offset = int(datetime(datetime.now(timezone.utc).year, 1, 1, 0, 0, 0,
                                       tzinfo=timezone.utc).timestamp()) * 10

    ptn = await get_int(ip, community, get_oid(NTCIP1202.Coord.Pattern.Status), port)

    controller_localtz_epoch, tz_differential = await asyncio.gather(
        get_int(ip, community, get_oid(NTCIP1202.Controller.LocalTime), port),
        get_int(ip, community, get_oid(NTCIP1202.Controller.StandardTimeZone), port),
    )

    if ptn < 254:
        split_tasks = [
            get_int(ip, community, get_oid(NTCIP1202.Coord.Split.Time, ptn, sg), port)
            for sg in sig_grps
        ]
        splits = await asyncio.gather(*split_tasks)

        for sg, split in zip(sig_grps, splits):
            entry = await _ensure_phase_timing_cached(ip, community, port, sg)
            min_ds = int(entry.min_grn) * 10
            # split is in seconds; yellow/red are deciseconds -> convert to seconds before subtraction, then back to ds
            max_ds = int(split - (entry.yellow / 10) - (entry.red / 10)) * 10
            time_to_change[sg] = {'min': min_ds, 'max': max_ds}

    else:
        for sg in sig_grps:
            entry = await _ensure_phase_timing_cached(ip, community, port, sg)
            min_ds = int(entry.min_grn) * 10
            max_ds = int(entry.max_grn) * 10
            time_to_change[sg] = {'min': min_ds, 'max': max_ds}

    if time_to_change[sg]['min'] > 35999:
        print(f"min time_to_change for sg {sg} goes over the hour ({time_to_change[sg]['min']}), subtracting 36000")
        time_to_change[sg]['min'] -= 36000
    
    if time_to_change[sg]['max'] > 35999:
        print(f"min time_to_change for sg {sg} goes over the hour ({time_to_change[sg]['max']}), subtracting 36000")
        time_to_change[sg]['max'] -= 36000

    controller_gmt_moy = (controller_localtz_epoch - tz_differential) * 10 - current_year_offset
    return [controller_gmt_moy, time_to_change]


@timed
async def get_signal_state(ip, community, int_id, sig_grps, tm):
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
                        "minEndTime": sg_ttc[1].get(sg).get('min') + tm,
                        "maxEndTime": sg_ttc[1].get(sg).get('max') + tm,
                    },
                }
            ],
        }
        )

    return sg_ttc[0], states


def compute_moy_and_time_mark():
    # TODO: Ideally this should be computed based on the controller's moy from get_phase_j2735_times_ntcip, but
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
        print(f"WARNING: Time mark out of range in compute_moy_and_time_mark(): {time_mark}")
        time_mark = 35999

    return moy, time_mark


@timed
async def build_spat_for_intersection(
    intersection_id,
    intersection_ip,
    moy,
    time_mark,
    signal_groups
):
    """
    Build a SPaT JER dict for a single intersection, given existing timing/state info.
    """

    states = await get_signal_state(intersection_ip, 'public', intersection_id, signal_groups, time_mark)

    spat = {
        "messageId": 19,
        "value": {
            "timeStamp": time_mark,  # DSecond-ish; still 0.1s from hour, but valid INTEGER
            "intersections": [
                {
                    "id": {"id": int(intersection_id)},
                    "revision": 0,
                    "status": "0000",
                    "moy": int(moy),
                    "timeStamp": time_mark,
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
        controller_time_synced = False
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

                if not controller_time_synced:
                    # Sync controller clocks with PC since virtual controllers run slow over time
                    current_datetime = int(datetime.now().timestamp())
                    await send_snmp_set_command(intersection_ip, 'administrator',
                                                NTCIP1202.Controller.GlobalTime, Counter32(current_datetime),
                                                intersection_id + 10000)
                    controller_time_synced = True

                spat_jer = await build_spat_for_intersection(
                    intersection_id,
                    intersection_ip,
                    moy,
                    time_mark,
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
