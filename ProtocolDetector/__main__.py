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
import yara
import sys
import struct
import argparse
import os


def check_yara(buf):
#  print buf
#  for character in buf:
#    sys.stdout.write(character.encode('hex'))
#  sys.stdout.flush()
#  print ''
  rules = yara.compile(filepath=os.path.dirname(__file__)+ os.sep + 'rules/index.yar')
  try:
    matches = rules.match(data=buf)
    if matches:
        return matches
  except TypeError:
    pass

def detect_protocol(buf):
    eth = dpkt.ethernet.Ethernet(buf)
    ip=eth.data
    tcp=ip.data 
    try:
        #print dir(tcp)
        buff = tcp.data
        matches = check_yara(buff)
        if matches is not None:
          print matches
    except AttributeError:
        print 'DEBUG: No payload'

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
            detect_protocol(buf)
    else:
        cap=pcapy.open_live(iface,100000,1,0)
        (header,payload)=cap.next()
        buf = str(payload)
        while header:
            detect_protocol(buf)
            # i need to know whether it is a tcp or  a udp packet here!!!
            (header,payload)=cap.next()

if __name__ == "__main__":
    main()