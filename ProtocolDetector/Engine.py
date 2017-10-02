#!/usr/bin/env python

#
#=============================================================================
#
# File Name         : Engine.py
# Author            : Jose Ramon Palanco   <jose.palanco@drainware.com>,
# Creation Date     : October 2017
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
import yara
import os
import socket


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
          src_ip = socket.inet_ntoa(ip.src)
          dst_ip = socket.inet_ntoa(ip.dst)
          return { 'protocols' : matches, 'dport': tcp.dport, 'sport': tcp.dport, 'src': src_ip, 'dst': dst_ip  }
    except AttributeError:
        print 'DEBUG: No payload'


def perform_check(buf):
    protocol = detect_protocol(buf)
    if protocol is not None:
        print protocol


def analyze_pcap(pcap_file):
    pcap_file = open(pcap_file)
    pcap=dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
        perform_check(buf)


def analyze_interface(iface):
    cap=pcapy.open_live(iface,100000,1,0)
    (header,payload)=cap.next()
    buf = str(payload)
    while header:
        perform_check(buf)
        # i need to know whether it is a tcp or  a udp packet here!!!
        (header,payload)=cap.next()