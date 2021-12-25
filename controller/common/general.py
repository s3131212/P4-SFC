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