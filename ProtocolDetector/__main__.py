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
    parser.add_argument('-rl', '--remove-local', help='Remove local network sources', action="store_true", required=False)

    args = parser.parse_args()
    mode = 'default'

    options = {'mode': 'default', 'socks_proxy': False, 'remove_local' : False, 'pcap_path': None, 'iface': None, 'rules' : None }


    if args.socks_proxy:
        options['socks_proxy'] = True

    if args.remove_local:
        options['remove_local'] = True


    if not args.interface:
        options['mode'] = 'pcap-file'
        if not args.pcapfile:
            print 'You need to provide or interface or pcapfile, please check options with --help'
            sys.exit(-1)

    options['pcap_path'] = args.pcapfile
    options['iface'] = args.interface
    options['rules'] = get_rules()


    if options['mode'] == 'pcap-file':
        analyze_pcap(options)
    else:
        analyze_interface(options)

if __name__ == "__main__":
    main()