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
        #analyze_pcap(pcap_file, network_mode='socks_proxy')
        analyze_pcap(pcap_file)
    else:
        analyze_interface(iface)

if __name__ == "__main__":
    main()