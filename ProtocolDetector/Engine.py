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
import pcapy
import yara
import os
import socket
import struct

#FIXME: Avoid compiling rules all the time
def check_yara(rules, buf):
#  print buf
#  for character in buf:
#    sys.stdout.write(character.encode('hex'))
#  sys.stdout.flush()
#  print ''
  try:
    matches = rules.match(data=buf)
    if matches:
        return matches
  except TypeError:
    pass

def detect_protocol(rules, buf):
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip=eth.data
        tcp=ip.data
        #print dir(tcp)
        buff = tcp.data
        matches = check_yara(rules, buff)
        ptype = None
        if type(ip.data) == dpkt.tcp.TCP:
            ptype = 'tcp'
        elif type(ip.data) == dpkt.udp.UDP:
            ptype = 'udp'
        if matches is not None:
          src_ip = socket.inet_ntoa(ip.src)
          dst_ip = socket.inet_ntoa(ip.dst)
        else:
            matches.append(ptype)
        return { 'protocols' : matches, 'dport': tcp.dport, 'sport': tcp.sport, 'src': src_ip, 'dst': dst_ip  }
    except AttributeError:
        pass
    except dpkt.dpkt.NeedData:
        pass

# FIXME: is not optimal parse everything all the time
def resolve_socks_proxy(pcap_path, sport):
    pcap_file = open(pcap_path)
    pcap=dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip=eth.data
        if type(ip.data) != dpkt.tcp.TCP or type(ip.data) != dpkt.udp.UDP:
            continue
        tcp=ip.data
        if tcp.dport == sport:
            # IMPORTAND: This is not a bug, we recover src as dst
            return { 'dport' : tcp.sport, 'dst': socket.inet_ntoa(ip.src) }


def perform_check(rules, buf, socks_proxy=False, pcap_path=None):
    protocol_details = detect_protocol(rules, buf)
    if protocol_details == None:
        return None
    if socks_proxy:
        socks_details = resolve_socks_proxy(pcap_path, protocol_details['sport'])
        protocol_details['dport'] = socks_details['dport']
        protocol_details['dst'] = socks_details['dst']
    return protocol_details

def get_rules():
    rules = yara.compile(filepath=os.path.dirname(__file__)+ os.sep + 'rules/index.yar')
    return rules

def analyze_pcap(pcap_path, mode=None):
    rules = get_rules()
    pcap_file = open(pcap_path)
    pcap=dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
        if mode == 'socks_proxy':
            results = perform_check(rules, buf, socks_proxy=True, pcap_path=pcap_path )
        else:
            results = perform_check(rules, buf)

        if results is not None:
            print results

def analyze_interface(iface):
    rules = get_rules()
    cap=pcapy.open_live(iface,100000,1,0)
    (header,payload)=cap.next()
    buf = str(payload)
    while header:
        perform_check(rules, buf)
        # i need to know whether it is a tcp or  a udp packet here!!!
        (header,payload)=cap.next()