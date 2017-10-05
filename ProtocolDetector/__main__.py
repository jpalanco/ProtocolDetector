#!/usr/bin/env python

#
#=============================================================================
#
# File Name         : __main__.py
# Author            : Jose Ramon Palanco   <jose.palanco@dinoflux.com>,
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

import sys
import struct
import argparse

from Engine import *



def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, help='Interface', required=False)
    parser.add_argument('-p', '--pcapfile', type=str, help='PCAP file path', required=False)
    parser.add_argument('-s', '--socks-proxy', help='Resolve socks proxy', action="store_true", required=False)
    args = parser.parse_args()
    mode = 'default'
    socks_proxy = False

    if args.socks_proxy:
        socks_proxy = True


    if not args.interface:
        mode = 'pcap-file'
        if not args.pcapfile:
            print 'You need to provide or interface or pcapfile, please check options with --help'
            sys.exit(-1)

    pcap_file = args.pcapfile
    iface = args.interface


    if mode == 'pcap-file':
        #analyze_pcap(pcap_file, network_mode='socks_proxy')
        if socks_proxy:
            analyze_pcap(pcap_file, mode='socks_proxy')
        else:
            analyze_pcap(pcap_file)
    else:
        if socks_proxy:
            analyze_pcap(pcap_file, mode='socks_proxy')
        else:
            analyze_pcap(pcap_file)

if __name__ == "__main__":
    main()