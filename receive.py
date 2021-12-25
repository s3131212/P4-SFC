#!/usr/bin/env python3
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import IP, UDP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    print("got a packet")
    pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()

# class SourceRoute(Packet):
#    fields_desc = [ BitField("bos", 0, 1),
#                    BitField("port", 0, 15)]
# class SourceRoutingTail(Packet):
#    fields_desc = [ XShortField("etherType", 0x800)]

class SFC_Header(Packet):
   fields_desc = [ BitField("version", 0, 2),
                   BitField("max_size", 0, 4), 
                   BitField("app_type", 0, 4),
                   BitField("qos", 0, 2),
                   BitField("dst_id", 0, 4)]

class SFC_Service(Packet):
   fields_desc = [ BitField("svc_type", 0, 6),
                   BitField("status", 0, 2), 
                   BitField("act", 0, 4),
                   BitField("params", 0, 4)]

class SFC_Context(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("content", 0, 15)]

class SFC_Context_Tail(Packet):
   fields_desc = [ XShortField("etherType", 0x800)]


bind_layers(Ether, SFC_Header, type=0x1234)
bind_layers(SFC_Header, SFC_Service)
bind_layers(SFC_Service, SFC_Context)
bind_layers(SFC_Context, SFC_Context, bos=0)
bind_layers(SFC_Context, IP, bos=1)
# bind_layers(SFC_Service, IP)

# bind_layers(Ether, SourceRoute, type=0x1234)
# bind_layers(SourceRoute, SourceRoute, bos=0)
# bind_layers(SourceRoute, SourceRoutingTail, bos=1)

def main():
    # iface = 'eth0'
    iface = 's4-eth1'
    # iface = 's4-eth2'
    # iface = 's2-eth1'
    # iface = 's2-eth2'
    iface = sys.argv[1]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    # sniff(filter="udp and port 4321", iface = iface,
    #       prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
