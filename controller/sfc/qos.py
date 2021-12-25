#!/usr/bin/env python3
import grpc
import os
import sys

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../'))

from common.const import *
from common.general import *
from common.rules import *

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