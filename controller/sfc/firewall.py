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
        write_check_ports_rule(p4info_helper, s3, ingress_port=1, egress_spec=2, direction=0)
        write_check_ports_rule(p4info_helper, s3, ingress_port=2, egress_spec=1, direction=1)
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