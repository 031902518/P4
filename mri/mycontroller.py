#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep

import grpc
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.error_utils import printGrpcError
import p4runtime_lib.helper
import p4runtime_lib.bmv2



def writeTunnelRules(p4info_helper, ingress_sw, ip_mac, ip,
                     ip_port, swid,howlong):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.swtrace",
        default_action = True,
        action_name="MyEgress.add_swtrace",
        action_params={
            "swid" : swid
        })
    ingress_sw.WriteTableEntry(table_entry)

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (ip, howlong)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr" : ip_mac,
            "port"    : ip_port
        })
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed ingress tunnel rule on %s" % ingress_sw.name)


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        # Create a switch connection object for s3
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")
        # s1
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s1,
                        ip_mac="08:00:00:00:01:01",ip="10.0.1.1",ip_port=2,swid=1,howlong=32)
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s1,
                        ip_mac="08:00:00:00:01:11",ip="10.0.1.11",ip_port=1,swid=1,howlong=32)
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s1,
                        ip_mac="08:00:00:00:02:00",ip="10.0.2.0",ip_port=3,swid=1,howlong=24)
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s1,
                        ip_mac="08:00:00:00:03:00",ip="10.0.3.0",ip_port=4,swid=1,howlong=24)

        #s2
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s2,
                        ip_mac="08:00:00:00:02:02",ip="10.0.2.2",ip_port=2,swid=2,howlong=32)
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s2,
                        ip_mac="08:00:00:00:02:22",ip="10.0.2.22",ip_port=1,swid=2,howlong=32)
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s2,
                        ip_mac="08:00:00:00:01:00",ip="10.0.1.0",ip_port=3,swid=2,howlong=24)
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s2,
                        ip_mac="08:00:00:00:03:00",ip="10.0.3.0",ip_port=4,swid=2,howlong=24)
        #s3
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s3,
                        ip_mac="08:00:00:00:03:03",ip="10.0.3.3",ip_port=1,swid=3,howlong=32)
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s3,
                        ip_mac="08:00:00:00:01:00",ip="10.0.1.0",ip_port=2,swid=3,howlong=24)
        writeTunnelRules(p4info_helper=p4info_helper,ingress_sw=s3,
                        ip_mac="08:00:00:00:02:00",ip="10.0.2.0",ip_port=3,swid=3,howlong=24)

        # Print the tunnel counters every 2 seconds
        while True:
            sleep(2)           

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" %
              args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)