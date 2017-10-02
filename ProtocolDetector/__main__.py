#!/usr/bin/env python

#
#=============================================================================
#
# File Name         : __main__.py
# Author            : Jose Ramon Palanco   <jose.palanco@drainware.com>,
# Creation Date     : September 2017
#
#
#
#=============================================================================
#
# PRODUCT           : ProtocolDetector
#
# MODULE            : 
#
# ROLE              : identification of protocols using Yara rules
#
# DEPENDANCE SYS.   : yara
#
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
#
#=============================================================================
#

import dpkt
import pcapy
import sys
import struct
import argparse

from Engine import *

def perform_check(buf):
    protocol = detect_protocol(buf)
    if protocol is not None:
        print protocol

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, help='Interface', required=False)
    parser.add_argument('-p', '--pcapfile', type=str, help='PCAP file path', required=False)
    args = parser.parse_args()
    mode = 'default'

    if not args.interface:
        mode = 'pcap-file'
        if not args.pcapfile:
            print 'You need to provide or interface or pcapfile, please check options with --help'
            sys.exit(-1)

    pcap_file = args.pcapfile
    iface = args.interface


    if mode == 'pcap-file':
        pcap_file = open(pcap_file)
        pcap=dpkt.pcap.Reader(pcap_file)
        for ts, buf in pcap:
            perform_check(buf)
    else:
        cap=pcapy.open_live(iface,100000,1,0)
        (header,payload)=cap.next()
        buf = str(payload)
        while header:
            perform_check(buf)
            # i need to know whether it is a tcp or  a udp packet here!!!
            (header,payload)=cap.next()

if __name__ == "__main__":
    main()