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

from find_carla_egg import find_carla_egg

carla_egg_file = find_carla_egg()

sys.path.append(carla_egg_file)

import carla

LOOP_DETECTORS = {
    "LD_1_2_STOP": {
        "intersection_id": 1,
        "signal_id": 102,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=-634.81, y=769.45, z=0.2),
            carla.Location(x=-634.81, y=776.45, z=0.2),
            carla.Location(x=-636.81, y=776.45, z=0.2),
            carla.Location(x=-636.81, y=769.45, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_1_2_ADV": {
        "intersection_id": 1,
        "signal_id": 102,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=-661.51, y=760.45, z=0.2),
            carla.Location(x=-664.01, y=767.05, z=0.2),
            carla.Location(x=-666.01, y=766.25, z=0.2),
            carla.Location(x=-663.51, y=759.65, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_1_4": {
        "intersection_id": 1,
        "signal_id": 101,
        "phase_id": 4,
        "bbox": [
            carla.Location(x=-620.61, y=758.55, z=0.2),
            carla.Location(x=-624.21, y=760.15, z=0.2),
            carla.Location(x=-625.11, y=758.15, z=0.2),
            carla.Location(x=-621.51, y=756.55, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_1_3": {
        "intersection_id": 1,
        "signal_id": 100,
        "phase_id": 3,
        "bbox": [
            carla.Location(x=-623.50, y=782.44, z=0.2),
            carla.Location(x=-620.99, y=782.44, z=0.2),
            carla.Location(x=-620.99, y=784.44, z=0.2),
            carla.Location(x=-623.60, y=784.44, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_2_2_STOP": {
        "intersection_id": 2,
        "signal_id": 201,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=-488.36, y=766.16, z=0.2),
            carla.Location(x=-488.36, y=773.15, z=0.2),
            carla.Location(x=-490.36, y=773.15, z=0.2),
            carla.Location(x=-490.36, y=766.16, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_2_2_ADV": {
        "intersection_id": 2,
        "signal_id": 201,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=-515.66, y=766.56, z=0.2),
            carla.Location(x=-515.66, y=773.65, z=0.2),
            carla.Location(x=-517.66, y=773.65, z=0.2),
            carla.Location(x=-517.66, y=766.44, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_2_8": {
        "intersection_id": 2,
        "signal_id": 202,
        "phase_id": 8,
        "bbox": [
            carla.Location(x=-477.59, y=757.05, z=0.2),
            carla.Location(x=-483.29, y=757.65, z=0.2),
            carla.Location(x=-483.29, y=755.65, z=0.2),
            carla.Location(x=-477.59, y=755.05, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_2_4": {
        "intersection_id": 2,
        "signal_id": 200,
        "phase_id": 4,
        "bbox": [
            carla.Location(x=-477.79, y=781.05, z=0.2),
            carla.Location(x=-471.59, y=780.85, z=0.2),
            carla.Location(x=-471.59, y=782.85, z=0.2),
            carla.Location(x=-477.79, y=783.05, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_3_2_STOP": {
        "intersection_id": 3,
        "signal_id": 300,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=-382.39, y=754.75, z=0.2),
            carla.Location(x=-381.59, y=761.95, z=0.2),
            carla.Location(x=-383.59, y=762.15, z=0.2),
            carla.Location(x=-384.39, y=755.05, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_3_2_ADV": {
        "intersection_id": 3,
        "signal_id": 300,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=-412.49, y=757.95, z=0.2),
            carla.Location(x=-411.79, y=764.95, z=0.2),
            carla.Location(x=-413.79, y=765.15, z=0.2),
            carla.Location(x=-414.49, y=758.05, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_4_2_STOP": {
        "intersection_id": 4,
        "signal_id": 400,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=-134.61, y=729.86, z=0.2),
            carla.Location(x=-134.00, y=736.83, z=0.2),
            carla.Location(x=-135.99, y=737.01, z=0.2),
            carla.Location(x=-136.60, y=730.03, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_4_2_ADV": {
        "intersection_id": 4,
        "signal_id": 400,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=-164.11, y=732.56, z=0.2),
            carla.Location(x=-163.50, y=739.53, z=0.2),
            carla.Location(x=-165.49, y=739.71, z=0.2),
            carla.Location(x=-166.10, y=732.73, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_4_8": {
        "intersection_id": 4,
        "signal_id": 401,
        "phase_id": 8,
        "bbox": [
            carla.Location(x=-122.40, y=720.83, z=0.2),
            carla.Location(x=-128.40, y=720.83, z=0.2),
            carla.Location(x=-128.40, y=718.83, z=0.2),
            carla.Location(x=-122.40, y=718.83, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_4_4": {
        "intersection_id": 4,
        "signal_id": 402,
        "phase_id": 4,
        "bbox": [
            carla.Location(x=-119.70, y=746.63, z=0.2),
            carla.Location(x=-125.70, y=746.63, z=0.2),
            carla.Location(x=-125.70, y=744.63, z=0.2),
            carla.Location(x=-119.70, y=744.63, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_5_2_STOP": {
        "intersection_id": 5,
        "signal_id": 500,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=52.30, y=710.11, z=0.2),
            carla.Location(x=52.91, y=717.08, z=0.2),
            carla.Location(x=50.91, y=717.26, z=0.2),
            carla.Location(x=50.30, y=710.29, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_5_2_ADV": {
        "intersection_id": 5,
        "signal_id": 500,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=20.40, y=713.31, z=0.2),
            carla.Location(x=21.01, y=720.28, z=0.2),
            carla.Location(x=19.01, y=720.46, z=0.2),
            carla.Location(x=18.40, y=713.49, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_5_8": {
        "intersection_id": 5,
        "signal_id": 502,
        "phase_id": 8,
        "bbox": [
            carla.Location(x=58.17, y=700.04, z=0.2),
            carla.Location(x=61.66, y=699.74, z=0.2),
            carla.Location(x=61.83, y=701.73, z=0.2),
            carla.Location(x=58.35, y=702.03, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_5_4": {
        "intersection_id": 5,
        "signal_id": 501,
        "phase_id": 4,
        "bbox": [
            carla.Location(x=64.02, y=723.26, z=0.2),
            carla.Location(x=68.01, y=722.91, z=0.2),
            carla.Location(x=68.18, y=724.91, z=0.2),
            carla.Location(x=64.20, y=725.26, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_6_2_STOP": {
        "intersection_id": 6,
        "signal_id": 600,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=232.18, y=704.88, z=0.2),
            carla.Location(x=229.46, y=715.03, z=0.2),
            carla.Location(x=227.53, y=714.51, z=0.2),
            carla.Location(x=230.24, y=704.37, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_6_2_ADV": {
        "intersection_id": 6,
        "signal_id": 600,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=190.15, y=697.30, z=0.2),
            carla.Location(x=190.15, y=705.30, z=0.2),
            carla.Location(x=188.15, y=705.30, z=0.2),
            carla.Location(x=188.15, y=697.30, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_6_8": {
        "intersection_id": 6,
        "signal_id": 601,
        "phase_id": 8,
        "bbox": [
            carla.Location(x=242.33, y=683.61, z=0.2),
            carla.Location(x=235.44, y=684.83, z=0.2),
            carla.Location(x=235.09, y=682.86, z=0.2),
            carla.Location(x=241.98, y=681.64, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_6_4": {
        "intersection_id": 6,
        "signal_id": 602,
        "phase_id": 4,
        "bbox": [
            carla.Location(x=253.45, y=726.17, z=0.2),
            carla.Location(x=249.52, y=726.87, z=0.2),
            carla.Location(x=249.17, y=724.90, z=0.2),
            carla.Location(x=253.11, y=724.20, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_7_2_STOP": {
        "intersection_id": 7,
        "signal_id": 700,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=358.99, y=717.17, z=0.2),
            carla.Location(x=359.69, y=723.97, z=0.2),
            carla.Location(x=357.69, y=724.27, z=0.2),
            carla.Location(x=356.99, y=717.37, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_7_2_ADV": {
        "intersection_id": 7,
        "signal_id": 700,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=329.09, y=720.07, z=0.2),
            carla.Location(x=329.59, y=726.77, z=0.2),
            carla.Location(x=327.59, y=726.87, z=0.2),
            carla.Location(x=327.09, y=720.17, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_8_2_STOP": {
        "intersection_id": 8,
        "signal_id": 900,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=531.69, y=838.79, z=0.2),
            carla.Location(x=532.91, y=845.68, z=0.2),
            carla.Location(x=530.94, y=846.03, z=0.2),
            carla.Location(x=529.73, y=839.14, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_8_2_ADV": {
        "intersection_id": 8,
        "signal_id": 900,
        "phase_id": 2,
        "bbox": [
            carla.Location(x=493.33, y=830.20, z=0.2),
            carla.Location(x=487.20, y=835.35, z=0.2),
            carla.Location(x=485.91, y=833.81, z=0.2),
            carla.Location(x=492.04, y=828.67, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_8_3": {
        "intersection_id": 8,
        "signal_id": 901,
        "phase_id": 3,
        "bbox": [
            carla.Location(x=538.60, y=829.93, z=0.2),
            carla.Location(x=534.61, y=830.28, z=0.2),
            carla.Location(x=534.44, y=828.29, z=0.2),
            carla.Location(x=538.42, y=827.94, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
    "LD_8_4": {
        "intersection_id": 8,
        "signal_id": 902,
        "phase_id": 4,
        "bbox": [
            carla.Location(x=547.47, y=851.82, z=0.2),
            carla.Location(x=544.09, y=852.73, z=0.2),
            carla.Location(x=543.57, y=850.80, z=0.2),
            carla.Location(x=546.95, y=849.89, z=0.2)
        ],
        "state": False,
        "prev_state": False
    },
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
        print(f"Error Status: {str(errorStatus)} at {errorIndex}")
    elif printval:
        for name, value in varBinds:
            print(f"{str(name)} = {str(value)}")

async def set_backup_time(engine, transport):
    await set_object_int(engine, transport, 'administrator', 0, NTCIP1202.Unit.BackupTime,
                         100, True)  # ensure backup time is set, not too high, not too low

def point_in_detector(location, bbox):
    """Evaluates if a point is within a loop detector"""
    def cross(a, b, p):
        # vector AB x AP
        return (b.x - a.x)*(p.y - a.y) - (b.y - a.y)*(p.x - a.x)
    
    signs = []
    for i in range(len(bbox)):
        a = bbox[i]
        b = bbox[(i + 1) % len(bbox)]
        signs.append(cross(a, b, location))

    all_positive = all(s > 0 for s in signs)
    all_negative = all(s < 0 for s in signs)

    return all_positive or all_negative

def draw_loop_detectors(dbg, detectors, life_time=0.0):
    """Draw loop detector bounding boxes"""
    for det in detectors.values():
        bbox = det["bbox"]

        for i in range (len(bbox)):
            start = bbox[i]
            end = bbox[(i+1) % len(bbox)]
            dbg.draw_line(start, end, life_time=life_time, thickness=0.1, color=carla.Color(0,255,0))

def on_state_change(detector_id, detector):
    """Dummy callback for something happening once the state has changed"""
    print(
        f"Loop Detector {detector_id} has changed state:"
        f"State Change: {'ON' if detector['prev_state']==True else 'OFF'} -> {'ON' if detector['state']==True else 'OFF'}"
    )

async def update_loop_detectors(world, detectors, engine, transport, intersection_id):
    vehicles = world.get_actors().filter("vehicle.*")
    tasks = []
    for det_id, det in detectors.items():
        if int(det["intersection_id"]) == int(intersection_id):
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
    argparser.add_argument('-I',
                           '--intersection-id',
                           type=int)
    argparser.add_argument('-d', '--display',
                           action='store_true',
                           help='Indicates that the program should draw the detector loops into CARLA')
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

    print("Loop detector event watcher running... (Ctrl+C to stop)")

    if args.intersection_id is None:
        int_id = str(int(args.snmp_port) - 10000)
    else:
        int_id = str(args.intersection_id)

    try:
        while True:
            if args.display:
                draw_loop_detectors(dbg, LOOP_DETECTORS, 0.2)
            await update_loop_detectors(world, LOOP_DETECTORS, engine, transport, int_id)
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        print("\nShutting down loop detector event watcher.")
    finally:
        pass


if __name__ == '__main__':
    asyncio.run(main())