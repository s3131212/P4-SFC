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
        write_sfc_service_rule(p4info_helper, s1, APP_TYPE_GENERAL, SVC_TYPE_PROXY)

        # s2
        write_drop_rule(p4info_helper, s2)
        write_sfc_enable_rule(p4info_helper, s2, "10.0.1.1", QOS_TOP, PROXY_DST_ID_1, APP_TYPE_GENERAL)
        write_sfc_forward_rule(p4info_helper, s2, APP_TYPE_GENERAL, PROXY_DST_ID_1, SVC_ACT_DEFAULT, 2, SVC_TYPE_QOS)
        write_sfc_forward_rule(p4info_helper, s2, APP_TYPE_GENERAL, PROXY_DST_ID_1, SVC_ACT_FIREWALL, 3, SVC_TYPE_QOS)
        write_sfc_disable_rule(p4info_helper, s2, "08:00:00:00:02:22", PROXY_DST_ID_2)
        write_sfc_service_rule(p4info_helper, s2, APP_TYPE_GENERAL, SVC_TYPE_PROXY)

        # Read table entries from s1
        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        
        # Close switch connections 
        ShutdownAllSwitchConnections()

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)