#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.fields import *
import readline

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

PROXY_DST_ID_1 = 11
PROXY_DST_ID_2 = 12

MID_PROXY_PORT_1 = 1
MID_PROXY_PORT_2 = 2

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

class SFC_Header(Packet):
   fields_desc = [ BitField("version", 0, 2),
                   BitField("max_size", 0, 4), 
                   BitField("type", 0, 4),
                   BitField("qos", 0, 2),
                   BitField("dst_id", 0, 4)]

class SFC_Service(Packet):
   fields_desc = [ BitField("type", 0, 6),
                   BitField("status", 0, 2), 
                   BitField("act", 0, 4),
                   BitField("params", 0, 4)]


# bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(Ether, SFC_Header, type=0x1234)
bind_layers(SFC_Header, SFC_Service)
bind_layers(SFC_Service, IP)

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(addr)))

    try:
        pkt = Ether(src=get_if_hwaddr(iface), dst="08:00:00:00:02:22")
        # pkt = pkt / SFC_Header(version=1, max_size=4, type=0, qos=1, dst_id=PROXY_DST_ID_1)
        # pkt = pkt / SFC_Service()
        # pkt = pkt / IP(dst=addr) / UDP(dport=4321, sport=1234)
        pkt = pkt / IP(dst=addr) / TCP(dport=4321, sport=1234)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
    except ValueError:
        pass

    # while True:
    #     print()
    #     s = str(input('Type space separated port nums '
    #                       '(example: "2 3 2 2 1") or "q" to quit: '))
    #     if s == "q":
    #         break;
    #     print()

    #     i = 0
    #     pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    #     for p in s.split(" "):
    #         try:
    #             pkt = pkt / SourceRoute(bos=0, port=int(p))
    #             i = i+1
    #         except ValueError:
    #             pass
    #     if pkt.haslayer(SourceRoute):
    #         pkt.getlayer(SourceRoute, i).bos = 1

    #     pkt = pkt / IP(dst=addr) / UDP(dport=4321, sport=1234)
    #     pkt.show2()
    #     sendp(pkt, iface=iface, verbose=False)

    #pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=3);
    #pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=2);
    #pkt = pkt / SourceRoute(bos=1, port=1)


if __name__ == '__main__':
    main()
