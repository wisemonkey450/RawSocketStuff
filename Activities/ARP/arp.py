#! /usr/bin/env python3

from scapy.all import *
import sys
import time
import struct

from netaddr import IPNetwork


class bc:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

def print_debug(mess):
    print(bc.HEADER + "[ " + time.asctime( time.localtime(time.time())  )+ "  ] " + bc.ENDC + bc.OKBLUE + mess + bc.ENDC)

def build_arp(dstip):
    b=ARP(op=0x01, hwsrc="fa:16:3e:d9:a9:cf", psrc="10.1.0.2", pdst=dstip)
    return

def build_ether():
    a=Ether(src="fa:16:3e:d9:a9:cf", dst="ff:ff:ff:ff:ff:ff", type= 0x0806)
    return a

def main():
    if len(sys.argv) < 2:
        print(bc.FAIL + "ERROR: Need to have IP subnet!" + bc.ENDC)
        exit(0)

    argc = len(sys.argv[1:])
    argv = sys.argv[1:]

    for ip in IPNetwork(argv[0]):
        print_debug("Creating ARP Packet from IP: " + str(ip))
        ether = build_ether()
        print(ether)
        exit(0)
        arp_frame = build_arp(ip)
        print_debug("Sending ARP Packet for IP: " + str(ip))
        sendp(ether / arp_frame, iface="eth0")
        print_debug("Sent ARP Packet for IP: " + str(ip))
        time.sleep(2)

if __name__ == "__main__":
    main()
