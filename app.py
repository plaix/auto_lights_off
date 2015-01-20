#!/usr/bin/env python

'''
File: app.py
Author: Sem Lievens
Description: Searches the network for multicast mDNS packages over 224.0.0.251 on port 5353 ( Bonjour IOS prot)
If none found, that means I'm out of the house, so kill all the lights
The timer_interval can be tweaked, I took a safe 25 min
'''

from scapy.all import *
from phue import Bridge

import sys
import argparse
import threading # needed for timer in background acting as a dead-man-switch
import logging
from logging.handlers import RotatingFileHandler

timer_interval=25
deadmanswitch= None

lgr = logging.getLogger('hue_service')
lgr.setLevel(logging.DEBUG)

fh = RotatingFileHandler('service.log',maxBytes=1024,backupCount=2)
fh.setLevel(logging.INFO)
frmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s [+] %(message)s')
fh.setFormatter(frmt)
# add the Handler to the logger
lgr.addHandler(fh)

def set_timer(result):
	global deadmanswitch
	# cancel if it was already running
	if deadmanswitch:
		lgr.debug("Resetting Timer...")
		deadmanswitch.cancel()
	lgr.debug("Starting Timer...")
	deadmanswitch=threading.Timer(60*timer_interval,kill_lights,[result.bridge])
	lgr.debug("Timer prepped...")
	deadmanswitch.daemon=True # needed for shutdown when main thead stops
	deadmanswitch.start()
	

def kill_lights(br):
    lgr.debug("Killing lights")	
    b=Bridge(br)
    b.connect()
    lights=b.get_light_objects()
    import random
    for light in lights:
	    light.on=False

# work with nested functions so we can pass the config
def search_phone(config):
	def sniff_bonjour(p):
		try:
			if p.haslayer(UDP) and p.src == config.mac and p[IP].dst == '224.0.0.251':
				lgr.debug("Found a correct bonjour packet!")
				set_timer(config)
		except IndexError:
			# We caught udp packets that aren't bonjour, just ignore and fail silently
			pass

	return sniff_bonjour


def argparser():
	parser=argparse.ArgumentParser(description='Auto hue shutdown script')
	parser.add_argument('-m','--mac',action="store",dest='mac',required=True,
			help='Mac addres for the IOS device to track')
	parser.add_argument('-i','--int',action="store",dest='iface',default="eth0",
			help='Interface to listen on, defaults to eth0')
	parser.add_argument('-b','--bridge_ip',action="store",dest='bridge',required=True,
			help='IP to Hue bridge')
	parser.add_argument('-d','--debug',action="store_const",dest='debug',const=True,
			help='debug mode on')
	parser.add_argument('--version',action='version',version='%(prog)s 1.0')
	return parser.parse_args()

if __name__ == '__main__':
	result=argparser()
	if result.debug:
		ch = logging.StreamHandler(sys.stdout)
		ch.setLevel(logging.DEBUG)
		vfrmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s [+] %(message)s')
		ch.setFormatter(vfrmt)
		lgr.addHandler(ch)

	set_timer(result)
	lgr.info("Sniffer started...")
	sniff(iface=result.iface, prn=search_phone(result), store=0)
