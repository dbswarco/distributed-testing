from pysnmp.hlapi.v3arch.asyncio import *
import logging

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

module_logger = logging.getLogger('main.snmp_getsetter')

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
            msg = f"{ip}:{port}: SNMP GET {oid} transport error: {error_indication}"
            module_logger.error(msg)
            raise SnmpGetError(msg)

        elif error_status:
            bad_var = (
                var_binds[int(error_index) - 1][0] if error_index else "unknown"
            )
            msg = (f"{ip}:{port}: SNMP GET {oid} agent error: "
                   f"{error_status.prettyPrint()} at {bad_var}")
            module_logger.error(msg)
            raise SnmpGetError(msg)

        value = var_binds[0][1]  # PySNMP type (e.g., Integer, OctetString)
        module_logger.debug(f"{ip}:{port}: SET {oid} {value.prettyPrint()}")
        return [ip, oid, value]

    finally:
        snmp_engine.close_dispatcher()
        #await asyncio.sleep(0.1)


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
            msg = f"{ip}:{port}: SNMP GET {oid} transport error: {error_indication}"
            module_logger.error(msg)
            raise SnmpGetError(msg)

        if error_status:
            bad_var = (
                var_binds[int(error_index) - 1][0] if error_index else "unknown"
            )
            msg = (f"{ip}:{port}: SNMP GET {oid} agent error: "
                   f"{error_status.prettyPrint()} at {bad_var}")
            module_logger.error(msg)
            raise SnmpGetError(msg)

        value = var_binds[0][1]  # PySNMP type (e.g., Integer, OctetString)
        module_logger.debug(f"{ip}:{port}: GET {oid} -> {value.prettyPrint()}")
        return [ip, oid, value]

    finally:
        snmp_engine.close_dispatcher()
        #await asyncio.sleep(0.1)


async def get_int(ip: str, community: str, oid: str, port: int) -> int:
    try:
        res = await send_snmp_get_command(ip, community, oid, port)
        if res is None:
            msg = f"{ip}:{port}: SNMP GET {oid} agent error: no value returned"
            raise SnmpGetError(msg)
        val = res[2]
        # Handle PySNMP types or plain Python types
        if hasattr(val, "prettyPrint"):
            val = val.prettyPrint()
        return int(val)  # works for int-ish strings as well
    except Exception as e:
        raise e