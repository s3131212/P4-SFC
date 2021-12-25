#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

PROXY_DST_ID_1 = 11
PROXY_DST_ID_2 = 12

MID_PROXY_PORT_1 = 1
MID_PROXY_PORT_2 = 2

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name, end=' ')
            for m in entry.match:
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('->', action_name, end=' ')
            for p in action.params:
                print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                print('%r' % p.value, end=' ')
            print()

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def connect_switch(name, device_id):
    port = 50050 + device_id + 1
    return p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=name,
            address=f'127.0.0.1:{port}',
            device_id=device_id,
            proto_dump_file=f'logs/{name}-p4runtime-requests.txt')

def master_arbitration_update(*args):
    for s in args:
        s.MasterArbitrationUpdate()

def connection_close(*args):
    for s in args:
        s.shutdown()

def set_forward_pipeline(sw, p4info_helper, bmv2_file_path):
    sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
    print(f"Installed P4 Program using SetForwardingPipelineConfig {sw.name}!")

def set_pipeline(p4info_helper, bmv2_file_path, *args):
    for sw in args:
        set_forward_pipeline(sw, p4info_helper, bmv2_file_path)

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

def write_forward_rule(p4info_helper, sw, dst_ip_addr, dst_eth_addr, port):
    """
    Install forwarding rules

    :param p4info_helper: the P4Info helper
    :param sw: the target switch
    :param dst_ip_addr: the destination IP to match in the forward rule
    :param dst_eth_addr: the destination ETH address to send to in the forward rule
    :param port: the switch port to send to in the forward rule
    """
    
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print("Installed forward rule on %s" % sw.name)

def write_proxy_enable_rule(p4info_helper, sw, dst_ip_addr, dst_id):
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.enable_sfc",
        action_params={
            "max_size": 4,
            "qos": 1,
            "dst_id": dst_id
        })
    sw.WriteTableEntry(table_entry)
    print("Installed sfc-enabled rule on %s" % sw.name)

def write_proxy_forward_rule(p4info_helper, sw, dst_id, port):
    # 2) Tunnel Transit Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sfc_forward_exact",
        # table_name="MyIngress.sfc_proxy_exact",
        match_fields={
            "hdr.sfc_header.dst_id": dst_id
        },
        action_name="MyIngress.forward_sfc",
        action_params={
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print("Installed proxy-transit rule on %s" % sw.name)

def write_proxy_disable_rule(p4info_helper, sw, dst_eth_addr, dst_id):
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
            "port": SWITCH_TO_HOST_PORT
        })
    sw.WriteTableEntry(table_entry)
    print("Installed proxy-disabled rule on %s" % sw.name)

def write_proxy_rules(p4info_helper, ingress_sw, egress_sw, dst_eth_addr, dst_ip_addr, dst_id, port):
    write_proxy_enable_rule(p4info_helper, ingress_sw, dst_ip_addr, dst_id)
    write_proxy_forward_rule(p4info_helper, ingress_sw, dst_id, port)
    write_proxy_disable_rule(p4info_helper, egress_sw, dst_eth_addr, dst_id)

def install_proxy(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = connect_switch('s1', 0)
        s2 = connect_switch('s2', 1)
        s4 = connect_switch('s4', 3)

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        master_arbitration_update(s1, s2, s4)

        # Install the P4 program on the switches
        # set_pipeline(p4info_helper, bmv2_file_path, s1, s2, s4)

        # Install drop rule
        write_drop_rule(p4info_helper, s1)
        write_drop_rule(p4info_helper, s2)
        write_drop_rule(p4info_helper, s4)
       
        # Install forward rules for s1
        # write_forward_rule(p4info_helper, s1, "10.0.1.1", "08:00:00:00:01:11", 1)
        # write_forward_rule(p4info_helper, s1, "10.0.2.2", "08:00:00:00:02:22", 2)

        # s1
        write_proxy_rules(p4info_helper, s1, s2, "08:00:00:00:02:22", "10.0.2.2", PROXY_DST_ID_1, SWITCH_TO_SWITCH_PORT)
        # write_proxy_enable_rule(p4info_helper, s1, "10.0.2.2", PROXY_DST_ID_1)
        # write_proxy_forward_rule(p4info_helper, s1, PROXY_DST_ID_1, SWITCH_TO_SWITCH_PORT)

        # s4
        write_proxy_forward_rule(p4info_helper, s4, PROXY_DST_ID_1, MID_PROXY_PORT_2)
        write_proxy_forward_rule(p4info_helper, s4, PROXY_DST_ID_2, MID_PROXY_PORT_1)

        # s2
        write_proxy_rules(p4info_helper, s2, s1, "08:00:00:00:01:11", "10.0.1.1", PROXY_DST_ID_2, SWITCH_TO_SWITCH_PORT)
        # write_proxy_forward_rule(p4info_helper, s2, PROXY_DST_ID_1, SWITCH_TO_HOST_PORT)


        # Read table entries from s1
        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s4)
        
        # Close switch connections 
        ShutdownAllSwitchConnections()
        # connection_close(s1, s2)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/sfc_proxy.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/sfc_proxy.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
        
    install_proxy(args.p4info, args.bmv2_json)
    
    
