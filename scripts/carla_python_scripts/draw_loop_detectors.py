import os
import sys
import re
import argparse
import json
import math
import time

from find_carla_egg import find_carla_egg

carla_egg_file = find_carla_egg()

sys.path.append(carla_egg_file)

import carla

argparser = argparse.ArgumentParser(
    description=__doc__)
argparser.add_argument(
    '--host',
    metavar='H',
    default='127.0.0.1',
    help='IP of the host server (default: 127.0.0.1)')
argparser.add_argument(
    '-p', '--port',
    metavar='P',
    default=2000,
    type=int,
    help='TCP port to listen to (default: 2000)')
argparser.add_argument(
    '-f', '--file',
    metavar='f',
    type=str,
    help='Import file to read crossing data')
args = argparser.parse_args()

def follow_vehicle_box(world, role_name, detector_area_width, detector_area_length, detector_area_box_thickness, detector_box_elevation, life_time=0.5,):
    """
    Continuously draw X/Y/Z axes at the vehicle's position.
    The draw frequency matches the life_time, so arrows refresh smoothly.

    Args:
        world: carla.World
        role_name: vehicle's role_name attribute to track
        life_time: seconds each arrow stays visible (also the update rate)
    """
    dbg = world.debug
    actors = world.get_actors().filter('vehicle.*')
    vehicle = next((a for a in actors if a.attributes.get('role_name') == role_name), None)
    if vehicle is None:
        print(f"Vehicle with role_name '{role_name}' not found.")
        return

    print(f"Tracking vehicle '{role_name}'... Press Ctrl+C to stop.")

    try:
        while True:
            transform = vehicle.get_transform()

            # # use your existing draw_world_axes()
            # draw_world_axes(world,
            #                 origin=origin,
            #                 length=length,
            #                 life_time=life_time,
            #                 persistent=False)

            # time.sleep(life_time)

            car_loc = carla.Location(transform.location.x, transform.location.y,detector_box_elevation)
            car_rot = transform.rotation

            car_box = carla.BoundingBox(car_loc,carla.Vector3D(detector_area_length/2,detector_area_width/2,0))

            
            dbg.draw_box(car_box,car_rot,thickness=detector_area_box_thickness,color=carla.Color(r=255,g=0,b=0),life_time=life_time)

            print(f'Current Veh Loc: {transform}')
            time.sleep(life_time)
    except KeyboardInterrupt:
        print("\nStopped following vehicle axes.")

try:
    client = carla.Client(args.host, args.port)
    client.set_timeout(5.0)
    world = client.get_world()
    dbg = world.debug
    # map = world.get_map()

    detector_area_width = 2 # in m
    detector_area_length = 4 # in m
    detector_area_box_thickness = 0.2
    detector_box_elevation = 0.5


    loop_detector_list = [
        carla.Transform(carla.Location(x=-138.163147, y=735.421082, z=-0.003079), carla.Rotation(pitch=0.051937, yaw=-7.201331, roll=-0.000153)),
        carla.Transform(carla.Location(x=-91.639610, y=729.618713, z=-0.003131), carla.Rotation(pitch=0.030941, yaw=-7.675024, roll=0.000220)),
    ]
    
    
    
    follow_vehicle_box(world, role_name="FHWA-M-3",detector_area_width=detector_area_width,detector_area_length=detector_area_length,detector_area_box_thickness=detector_area_box_thickness, detector_box_elevation=detector_box_elevation, life_time=1)

    for loop in loop_detector_list:
        loop = carla.Transform(carla.Location(loop.location.x,loop.location.y,detector_box_elevation), loop.rotation) 

        print(f"drawing: {loop}")

        box = carla.BoundingBox(loop.location,carla.Vector3D(detector_area_length/2,detector_area_width/2,0))

        dbg.draw_box(box,loop.rotation,thickness=detector_area_box_thickness,color=carla.Color(r=255,g=0,b=0),life_time=5)
    

    
    
    
    

finally:
    print('\nDone!')