#!/usr/bin/env python3
import grpc
import os
import sys

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def write_drop_rule(p4info_helper, sw):
    """
    Write drop rule to switches.

    :param p4info_helper: the P4Info helper
    :param sw: the target switch
    """

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        default_action=True,
        action_name="MyIngress.drop")

    sw.WriteTableEntry(table_entry)
    print("Installed drop rule on %s" % sw.name)

def write_sfc_enable_rule(p4info_helper, sw, dst_ip_addr, qos, dst_id, app_type):
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.enable_sfc",
        action_params={
            "max_size": 4,
            "qos": qos,
            "dst_id": dst_id,
            "app_type": app_type
        })
    sw.WriteTableEntry(table_entry)
    print("Installed sfc-enabled rule on %s" % sw.name)

def write_sfc_forward_rule(p4info_helper, sw, app_type, dst_id, act, port, svc_type):
    # 2) Tunnel Transit Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sfc_forward_exact",
        # table_name="MyIngress.sfc_proxy_exact",
        match_fields={
            "hdr.sfc_header.app_type": app_type,
            "hdr.sfc_header.dst_id": dst_id,
            "hdr.sfc_service.act": act
        },
        action_name="MyIngress.forward_sfc",
        action_params={
            "port": port,
            "svc_type": svc_type
        })

    sw.WriteTableEntry(table_entry)
    print("Installed proxy-transit rule on %s" % sw.name)

def write_sfc_disable_rule(p4info_helper, sw, dst_eth_addr, dst_id):
    # 3) Tunnel Egress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sfc_disable_exact",
        # table_name="MyIngress.sfc_proxy_exact",
        match_fields={
            "hdr.sfc_header.dst_id": dst_id
        },
        action_name="MyIngress.disable_sfc",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": 1
        })
    sw.WriteTableEntry(table_entry)
    print("Installed proxy-disabled rule on %s" % sw.name)

def write_sfc_service_rule(p4info_helper, sw, app_type, svc_type):
    # 2) Tunnel Transit Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sfc_service_exact",
        # table_name="MyIngress.sfc_proxy_exact",
        match_fields={
            "hdr.sfc_header.app_type": app_type,
            "hdr.sfc_service.svc_type": svc_type
        },
        action_name="MyIngress.check_sfc_service",
        action_params={}
        )
    sw.WriteTableEntry(table_entry)
    print("Installed proxy-transit rule on %s" % sw.name)

def write_check_ports_rule(p4info_helper, sw, ingress_port, egress_spec, direction):
    """
    Install port-checking rules

    :param p4info_helper: the P4Info helper
    :param sw: the target switch
    :param ingress_port: the ingress port of a packet
    :param egress_spec: the egress spec (port) of a packet
    :param direction: packet direction, value is 0 or 1 (internal or external)
    """
    
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.check_ports",
        match_fields={
            "standard_metadata.ingress_port": ingress_port,
            "standard_metadata.egress_spec": egress_spec,
        },
        action_name="MyIngress.set_direction",
        action_params={
            "dir": direction
        })
    sw.WriteTableEntry(table_entry)
    print("Installed check ports rule on %s" % sw.name)