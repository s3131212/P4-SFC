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


PROXY_DST_ID_1 = 11
PROXY_DST_ID_2 = 12

MID_PROXY_PORT_1 = 1
MID_PROXY_PORT_2 = 2
MID_PROXY_PORT_3 = 3
MID_PROXY_PORT_4 = 4

APP_TYPE_GENERAL = 0
APP_TYPE_WEB = 1

SVC_TYPE_PROXY = 0
SVC_TYPE_FIREWALL = 1
SVC_TYPE_QOS = 2
SVC_TYPE_LOAD_BALANCE = 3

SVC_ACT_DEFAULT = 0
SVC_ACT_FIREWALL = 1

QOS_TOP = 0
QOS_HIGH = 1
QOS_MEDIUM = 2
QOS_LOW = 3

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

def install_proxy(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s1 = connect_switch('s1', 0)
        s2 = connect_switch('s2', 1)

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        master_arbitration_update(s1, s2)

        # Install the P4 program on the switches
        set_pipeline(p4info_helper, bmv2_file_path, s1, s2)

        # s1
        write_drop_rule(p4info_helper, s1)
        write_sfc_enable_rule(p4info_helper, s1, "10.0.2.2", QOS_TOP, PROXY_DST_ID_2, APP_TYPE_GENERAL)
        write_sfc_forward_rule(p4info_helper, s1, APP_TYPE_GENERAL, PROXY_DST_ID_2, SVC_ACT_FIREWALL, 3, SVC_TYPE_FIREWALL)
        write_sfc_forward_rule(p4info_helper, s1, APP_TYPE_GENERAL, PROXY_DST_ID_2, SVC_ACT_DEFAULT, 2, SVC_TYPE_QOS)
        write_sfc_disable_rule(p4info_helper, s1, "08:00:00:00:01:11", PROXY_DST_ID_1)

        # s2
        write_drop_rule(p4info_helper, s2)
        write_sfc_enable_rule(p4info_helper, s2, "10.0.1.1", QOS_TOP, PROXY_DST_ID_1, APP_TYPE_GENERAL)
        write_sfc_forward_rule(p4info_helper, s2, APP_TYPE_GENERAL, PROXY_DST_ID_1, SVC_ACT_DEFAULT, 2, SVC_TYPE_QOS)
        write_sfc_forward_rule(p4info_helper, s2, APP_TYPE_GENERAL, PROXY_DST_ID_1, SVC_ACT_FIREWALL, 3, SVC_TYPE_QOS)
        write_sfc_disable_rule(p4info_helper, s2, "08:00:00:00:02:22", PROXY_DST_ID_2)


        # Read table entries from s1
        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        
        # Close switch connections 
        ShutdownAllSwitchConnections()

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

def install_firewall(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s3 = connect_switch('s3', 2)

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        master_arbitration_update(s3)

        # Install the P4 program on the switches
        set_pipeline(p4info_helper, bmv2_file_path, s3)

        # s4
        write_sfc_forward_rule(p4info_helper, s3, APP_TYPE_GENERAL, PROXY_DST_ID_1, SVC_ACT_DEFAULT, 1, SVC_TYPE_PROXY)
        write_sfc_forward_rule(p4info_helper, s3, APP_TYPE_GENERAL, PROXY_DST_ID_2, SVC_ACT_DEFAULT, 2, SVC_TYPE_QOS)
        write_sfc_service_rule(p4info_helper, s3, APP_TYPE_GENERAL, SVC_TYPE_FIREWALL)

        # Read table entries from s1
        readTableRules(p4info_helper, s3)
        
        # Close switch connections 
        ShutdownAllSwitchConnections()

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

def install_qos(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s4 = connect_switch('s4', 3)

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        master_arbitration_update(s4)

        # Install the P4 program on the switches
        set_pipeline(p4info_helper, bmv2_file_path, s4)

        # s4
        write_sfc_forward_rule(p4info_helper, s4, APP_TYPE_GENERAL, PROXY_DST_ID_1, SVC_ACT_DEFAULT, 1, SVC_TYPE_PROXY)
        write_sfc_forward_rule(p4info_helper, s4, APP_TYPE_GENERAL, PROXY_DST_ID_1, SVC_ACT_FIREWALL, 3, SVC_TYPE_FIREWALL)
        write_sfc_forward_rule(p4info_helper, s4, APP_TYPE_GENERAL, PROXY_DST_ID_2, SVC_ACT_DEFAULT, 2, SVC_TYPE_PROXY)
        write_sfc_forward_rule(p4info_helper, s4, APP_TYPE_GENERAL, PROXY_DST_ID_2, SVC_ACT_FIREWALL, 4, SVC_TYPE_PROXY)

        write_sfc_service_rule(p4info_helper, s4, APP_TYPE_GENERAL, SVC_TYPE_QOS)

        # Read table entries from s1
        readTableRules(p4info_helper, s4)
        
        # Close switch connections 
        ShutdownAllSwitchConnections()

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description='P4Runtime Controller')
    # parser.add_argument('--p4info', help='p4info proto in text format from p4c',
    #                     type=str, action="store", required=False,
    #                     default='./build/sfc_proxy.p4.p4info.txt')
    # parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
    #                     type=str, action="store", required=False,
    #                     default='./build/sfc_proxy.json')
    # args = parser.parse_args()

    # if not os.path.exists(args.p4info):
    #     parser.print_help()
    #     print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
    #     parser.exit(1)
    # if not os.path.exists(args.bmv2_json):
    #     parser.print_help()
    #     print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
    #     parser.exit(1)
        
    install_proxy('./build/sfc_proxy.p4.p4info.txt', './build/sfc_proxy.json')
    install_firewall('./build/sfc_firewall.p4.p4info.txt', './build/sfc_firewall.json')
    install_qos('./build/sfc_qos.p4.p4info.txt', './build/sfc_qos.json')
    
    
