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
                 '../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

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

def install_basic(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s2, s3, and s4;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s2 = connect_switch('s2', 1)
        s3 = connect_switch('s3', 2)
        s4 = connect_switch('s4', 3)

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        master_arbitration_update(s2, s3, s4)

        # Install the P4 program on the switches
        set_pipeline(p4info_helper, bmv2_file_path, s2, s3, s4)
   
        # Install drop rule on all switch
        write_drop_rule(p4info_helper, s2)
        write_drop_rule(p4info_helper, s3)
        write_drop_rule(p4info_helper, s4)
        

        # Install forward rules for s2
        write_forward_rule(p4info_helper, s2, "10.0.1.1", "08:00:00:00:03:00", 4)
        write_forward_rule(p4info_helper, s2, "10.0.2.2", "08:00:00:00:04:00", 3)
        write_forward_rule(p4info_helper, s2, "10.0.3.3", "08:00:00:00:03:33", 1)
        write_forward_rule(p4info_helper, s2, "10.0.4.4", "08:00:00:00:04:44", 1)

       # Install forward rules for s3
        write_forward_rule(p4info_helper, s3, "10.0.1.1", "08:00:00:00:01:00", 1)
        write_forward_rule(p4info_helper, s3, "10.0.2.2", "08:00:00:00:01:00", 1)
        write_forward_rule(p4info_helper, s3, "10.0.3.3", "08:00:00:00:02:00", 2)
        write_forward_rule(p4info_helper, s3, "10.0.4.4", "08:00:00:00:02:00", 2)

       # Install forward rules for s4
        write_forward_rule(p4info_helper, s4, "10.0.1.1", "08:00:00:00:01:00", 2)
        write_forward_rule(p4info_helper, s4, "10.0.2.2", "08:00:00:00:01:00", 2)
        write_forward_rule(p4info_helper, s4, "10.0.3.3", "08:00:00:00:02:00", 1)
        write_forward_rule(p4info_helper, s4, "10.0.4.4", "08:00:00:00:02:00", 1)

        # Read table entries from switches
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s3)
        readTableRules(p4info_helper, s4)

        # Close switch connection
        connection_close(s2, s3, s4)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

def install_firewall(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = connect_switch('s1', 0)

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        master_arbitration_update(s1)

        # Install the P4 program on the switches
        set_pipeline(p4info_helper, bmv2_file_path, s1)

        # Install drop rule
        write_drop_rule(p4info_helper, s1)
       
        # Install forward rules for s1
        write_forward_rule(p4info_helper, s1, "10.0.1.1", "08:00:00:00:01:11", 1)
        write_forward_rule(p4info_helper, s1, "10.0.2.2", "08:00:00:00:02:22", 2)
        write_forward_rule(p4info_helper, s1, "10.0.3.3", "08:00:00:00:03:00", 3)
        write_forward_rule(p4info_helper, s1, "10.0.4.4", "08:00:00:00:04:00", 4)

        # Install port-checking rules on the switches
        write_check_ports_rule(p4info_helper, s1, ingress_port=1, egress_spec=3, direction=0)
        write_check_ports_rule(p4info_helper, s1, ingress_port=1, egress_spec=4, direction=0)
        write_check_ports_rule(p4info_helper, s1, ingress_port=2, egress_spec=3, direction=0)
        write_check_ports_rule(p4info_helper, s1, ingress_port=2, egress_spec=4, direction=0)
        write_check_ports_rule(p4info_helper, s1, ingress_port=3, egress_spec=1, direction=1)
        write_check_ports_rule(p4info_helper, s1, ingress_port=3, egress_spec=2, direction=1)
        write_check_ports_rule(p4info_helper, s1, ingress_port=4, egress_spec=1, direction=1)
        write_check_ports_rule(p4info_helper, s1, ingress_port=4, egress_spec=2, direction=1)

        # Read table entries from s1
        readTableRules(p4info_helper, s1)
        
        # Close switch connections 
        connection_close(s1)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/firewall.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/firewall.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    install_basic('./build/basic.p4.p4info.txt', './build/basic.json')
    install_firewall(args.p4info, args.bmv2_json)
    
    ShutdownAllSwitchConnections()
