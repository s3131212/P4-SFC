#!/usr/bin/env python3
#
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import argparse
import json
import os
import sys
from time import sleep

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
from p4runtime_lib import bmv2, helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

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

def error(msg):
    print(' - ERROR! ' + msg, file=sys.stderr)

def info(msg):
    print(' - ' + msg, file=sys.stdout)

class ConfException(Exception):
    pass

def check_switch_conf(sw_conf, workdir):
    required_keys = ["p4info"]
    files_to_check = ["p4info"]
    target_choices = ["bmv2"]

    if "target" not in sw_conf:
        raise ConfException("missing key 'target'")
    target = sw_conf['target']
    if target not in target_choices:
        raise ConfException("unknown target '%s'" % target)

    if target == 'bmv2':
        required_keys.append("bmv2_json")
        files_to_check.append("bmv2_json")

    for conf_key in required_keys:
        if conf_key not in sw_conf or len(sw_conf[conf_key]) == 0:
            raise ConfException("missing key '%s' or empty value" % conf_key)

    for conf_key in files_to_check:
        real_path = os.path.join(workdir, sw_conf[conf_key])
        if not os.path.exists(real_path):
            raise ConfException("file does not exist %s" % real_path)


def program_switch(addr, device_id, sw_conf_file, workdir, proto_dump_fpath):
    sw_conf = json_load_byteified(sw_conf_file)
    try:
        check_switch_conf(sw_conf=sw_conf, workdir=workdir)
    except ConfException as e:
        error("While parsing input runtime configuration: %s" % str(e))
        return

    info('Using P4Info file %s...' % sw_conf['p4info'])
    p4info_fpath = os.path.join(workdir, sw_conf['p4info'])
    p4info_helper = helper.P4InfoHelper(p4info_fpath)

    target = sw_conf['target']

    info("Connecting to P4Runtime server on %s (%s)..." % (addr, target))

    if target == "bmv2":
        sw = bmv2.Bmv2SwitchConnection(address=addr, device_id=device_id,
                                       proto_dump_file=proto_dump_fpath)
    else:
        raise Exception("Don't know how to connect to target %s" % target)

    try:
        sw.MasterArbitrationUpdate()

        if target == "bmv2":
            info("Setting pipeline config (%s)..." % sw_conf['bmv2_json'])
            bmv2_json_fpath = os.path.join(workdir, sw_conf['bmv2_json'])
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_json_fpath)
        else:
            raise Exception("Should not be here")

        if 'table_entries' in sw_conf:
            table_entries = sw_conf['table_entries']
            info("Inserting %d table entries..." % len(table_entries))
            for entry in table_entries:
                info(tableEntryToString(entry))
                insertTableEntry(sw, entry, p4info_helper)

        if 'multicast_group_entries' in sw_conf:
            group_entries = sw_conf['multicast_group_entries']
            info("Inserting %d group entries..." % len(group_entries))
            for entry in group_entries:
                info(groupEntryToString(entry))
                insertMulticastGroupEntry(sw, entry, p4info_helper)

        if 'clone_session_entries' in sw_conf:
            clone_entries = sw_conf['clone_session_entries']
            info("Inserting %d clone entries..." % len(clone_entries))
            for entry in clone_entries:
                info(cloneEntryToString(entry))
                insertCloneGroupEntry(sw, entry, p4info_helper)

    finally:
        sw.shutdown()


def insertTableEntry(sw, flow, p4info_helper):
    table_name = flow['table']
    match_fields = flow.get('match') # None if not found
    action_name = flow['action_name']
    default_action = flow.get('default_action') # None if not found
    action_params = flow['action_params']
    priority = flow.get('priority')  # None if not found

    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        priority=priority)

    sw.WriteTableEntry(table_entry)


def json_load_byteified(file_handle):
    return json.load(file_handle)


def _byteify(data, ignore_dicts=False):
    # if this is a unicode string, return its string representation
    if isinstance(data, str):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.items()
        }
    # if it's anything else, return it in its original form
    return data


def tableEntryToString(flow):
    if 'match' in flow:
        match_str = ['%s=%s' % (match_name, str(flow['match'][match_name])) for match_name in
                     flow['match']]
        match_str = ', '.join(match_str)
    elif 'default_action' in flow and flow['default_action']:
        match_str = '(default action)'
    else:
        match_str = '(any)'
    params = ['%s=%s' % (param_name, str(flow['action_params'][param_name])) for param_name in
              flow['action_params']]
    params = ', '.join(params)
    return "%s: %s => %s(%s)" % (
        flow['table'], match_str, flow['action_name'], params)


def groupEntryToString(rule):
    group_id = rule["multicast_group_id"]
    replicas = ['%d' % replica["egress_port"] for replica in rule['replicas']]
    ports_str = ', '.join(replicas)
    return 'Group {0} => ({1})'.format(group_id, ports_str)

def cloneEntryToString(rule):
    clone_id = rule["clone_session_id"]
    if "packet_length_bytes" in rule:
        packet_length_bytes = str(rule["packet_length_bytes"])+"B"
    else:
        packet_length_bytes = "NO_TRUNCATION"
    replicas = ['%d' % replica["egress_port"] for replica in rule['replicas']]
    ports_str = ', '.join(replicas)
    return 'Clone Session {0} => ({1}) ({2})'.format(clone_id, ports_str, packet_length_bytes)

def insertMulticastGroupEntry(sw, rule, p4info_helper):
    mc_entry = p4info_helper.buildMulticastGroupEntry(rule["multicast_group_id"], rule['replicas'])
    sw.WritePREEntry(mc_entry)

def insertCloneGroupEntry(sw, rule, p4info_helper):
    clone_entry = p4info_helper.buildCloneSessionEntry(rule['clone_session_id'], rule['replicas'],
                                                       rule.get('packet_length_bytes', 0))
    sw.WritePREEntry(clone_entry)


def main():
    parser = argparse.ArgumentParser(description='P4Runtime Simple Controller')

    parser.add_argument('-a', '--p4runtime-server-addr',
                        help='address and port of the switch\'s P4Runtime server (e.g. 172.0.0.1:50051)',
                        type=str, action="store", required=True)
    parser.add_argument('-d', '--device-id',
                        help='Internal device ID to use in P4Runtime messages',
                        type=int, action="store", required=True)
    parser.add_argument('-p', '--proto-dump-file',
                        help='path to file where to dump protobuf messages sent to the switch',
                        type=str, action="store", required=True)
    parser.add_argument("-c", '--runtime-conf-file',
                        help="path to input runtime configuration file (JSON)",
                        type=str, action="store", required=True)

    args = parser.parse_args()

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
    if not os.path.exists(args.runtime_conf_file):
        parser.error("File %s does not exist!" % args.runtime_conf_file)
    workdir = os.path.dirname(os.path.abspath(args.runtime_conf_file))
    with open(args.runtime_conf_file, 'r') as sw_conf_file:
        program_switch(addr=args.p4runtime_server_addr,
                       device_id=args.device_id,
                       sw_conf_file=sw_conf_file,
                       workdir=workdir,
                       proto_dump_fpath=args.proto_dump_file)

if __name__ == '__main__':
    main()
