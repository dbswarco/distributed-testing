import sys
import argparse
import time

# pip install pysnmp~=7.1.20 setuptools~=80.3.1
import asyncio
import enum
from pysnmp.hlapi.v3arch.asyncio import (
    Integer, set_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)

# from find_carla_egg import find_carla_egg

# carla_egg_file = find_carla_egg()

# sys.path.append(carla_egg_file)

import carla

LOOP_DETECTORS = {
    "LD_1_1": {
        "intersection_id": 1,
        "signal_id": 100,
        "phase_id": 2,
        "bbox": {
            "min": carla.Location(x=-636.800781,y=769.605347,z=0.2),
            "max": carla.Location(x=-634.800781,y=776.605347,z=0.2),
        },
        "state": False,
        "prev_state": False
    }
}

# This class definition is only required for Python < 3.11. 3.11+ supports StrEnum, ex. `MyClass(enum.StrEnum)`.
class StrEnum(str, enum.Enum):
    pass
class NTCIP1202:
    @enum.unique
    class Unit(StrEnum):
        BackupTime = '1.3.6.1.4.1.1206.4.2.1.3.3'
class McCain:
    @enum.unique
    class DetectorControlState(StrEnum):
        Vehicle = '1.3.6.1.4.1.1206.3.21.2.13.4.1.1'
        Pedestrian = '1.3.6.1.4.1.1206.3.21.2.14.4.1.1'

async def snmp_connect(host, port):
    try:
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create((host, port))
        return engine, transport
    except Exception as e:
        print(f"Fatal error in omni {host}:{port}: {e}")
        while True:
            await asyncio.sleep(10)  # Prevent container from exiting

async def set_object_int(engine, transport, community, version, OID, val, printval=False):
    errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
        engine,
        CommunityData(community, mpModel=version),
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(OID), Integer(val))
    )
    if errorIndication:
        print(f"Error: {errorIndication}")
    elif errorStatus:
        print(f"Error Status: {errorStatus.prettyPrint()} at {errorIndex}")
    elif printval:
        for name, val in varBinds:
            print(f"{name.prettyPrint()} = {val.prettyPrint()}")

async def set_backup_time(engine, transport):
    await set_object_int(engine, transport, 'administrator', 0, NTCIP1202.Unit.BackupTime,
                         100, True)  # ensure backup time is set, not too high, not too low

def point_in_detector(location, bbox):
    """Evaluates if a point is within a loop detector"""
    return (
        bbox["min"].x <= location.x <= bbox["max"].x and
        bbox["min"].y <= location.y <= bbox["max"].y
        #bbox["min"].z <= location.z <= bbox["max"].z
    )

def draw_loop_detectors(dbg, detectors, life_time=0.0):
    """Draw loop detector bounding boxes"""
    for det in detectors.values():
        bbox = det["bbox"]

        center = (bbox["min"] + bbox["max"]) * 0.5
        extent = (bbox["max"] - bbox["min"]) * 0.5

        dbg.draw_box(
            box=carla.BoundingBox(center, extent),
            rotation=carla.Rotation(),
            thickness=0.1,
            color=carla.Color(0, 255, 0),
            life_time=life_time
        )

def on_state_change(detector_id, detector):
    """Dummy callback for something happening once the state has changed"""
    print(
        f"Loop Detector {detector_id} has changed state:"
        f"State Change: {'ON' if detector['prev_state']==True else 'OFF'} -> {'ON' if detector['state']==True else 'OFF'}"
    )

async def update_loop_detectors(world, detectors, engine, transport):
    vehicles = world.get_actors().filter("vehicle.*")
    tasks = []
    for det_id, det in detectors.items():
        det["prev_state"] = det["state"]
        det["state"] = False

        bbox = det["bbox"]

        for vehicle in vehicles:
            vehicle_loc = vehicle.get_location()
            if point_in_detector(vehicle_loc, bbox):
                det["state"] = True
                break
        
        if det["state"] != det["prev_state"]:
            on_state_change(det_id, det)
            task = set_object_int(engine, transport, 'administrator', 0,
                                  McCain.DetectorControlState.Vehicle + '.' + str(det["phase_id"]),
                                  int(det["state"]), True)
            tasks.append(task)

    if tasks:
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            print(f"Fatal error: {e}")
            while True:
                await asyncio.sleep(10)  # Prevent container from exiting


async def main():
    argparser = argparse.ArgumentParser(description="CARLA loop detector SNMP updater")
    argparser.add_argument('--host', 
                           default='127.0.0.1', 
                           help='CARLA host (default: 127.0.0.1)')
    argparser.add_argument('-p', 
                           '--port', 
                           default=2000, 
                           type=int, 
                           help='CARLA port (default: 2000)')
    argparser.add_argument('-C', 
                           '--controller', 
                           default='10.1.110.183', 
                           help='Controller IP')
    argparser.add_argument('-S', 
                           '--snmp-port', 
                           default=10001, 
                           type=int, 
                           help='Controller SNMP UDP port')
    args = argparser.parse_args()

    # # Windows: use selector-based loop
    # if sys.platform.startswith("win"):
    #     try:
    #         asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    #     except Exception:
    #         pass

    client = carla.Client(args.host, args.port)
    client.set_timeout(5.0)
    world = client.get_world()
    dbg = world.debug

    engine, transport = await snmp_connect(args.controller, args.snmp_port)

    # Prepare controller
    await set_backup_time(engine, transport)

    draw_loop_detectors(dbg, LOOP_DETECTORS)
    print("Loop detector event watcher running... (Ctrl+C to stop)")

    try:
        while True:
            await update_loop_detectors(world, LOOP_DETECTORS, engine, transport)
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        print("\nShutting down loop detector event watcher.")
    finally:
        await transport.close()
        pass


if __name__ == '__main__':
    asyncio.run(main())