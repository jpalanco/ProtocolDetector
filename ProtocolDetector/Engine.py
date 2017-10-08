#!/usr/bin/env python

#
#=============================================================================
#
# File Name         : Engine.py
# Author            : Jose Ramon Palanco   <jose.palanco@dinoflux.com>,
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
from IPy import IP

def check_yara(rules, buf):
#  print buf
#  for character in buf:
#    sys.stdout.write(character.encode('hex'))
#  sys.stdout.flush()
#  print ''
  try:
    matches = rules.match(data=buf)
    results = []
    for match in matches:
        results.append(match.rule)

    if results:
        return results
    else:
        return []
  except TypeError as e:
    pass

def detect_protocol(buf, options):
    rules = options['rules']
    ptype = None
    data_buf = None
    dport = None
    sport = None


    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip=eth.data


        if type(ip.data) == dpkt.icmp.ICMP:
            return

        if type(ip.data) == dpkt.tcp.TCP:
            ptype = 'tcp'
            tcp=ip.data
            data_buf = tcp.data
            dport = tcp.dport
            sport = tcp.sport

        elif type(ip.data) == dpkt.udp.UDP:
            ptype = 'udp'
            udp=ip.data
            data_buf = udp.data
            dport = udp.dport
            sport = udp.sport

        matches = check_yara(rules, data_buf)


        try:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
        except socket.error:
            return None

        #if matches is None:
        #    matches = []
        #    matches.append(ptype)

        if len(matches)<1:
            return None
            #matches.append(ptype)

        if options['remove_local']:
            ip = IP(dst_ip)
            if ip.iptype() == 'PRIVATE':
                return None

        return { 'protocols' : matches, 'dport': dport, 'sport': sport, 'src': src_ip, 'dst': dst_ip  }
    except AttributeError:
        pass
    except dpkt.dpkt.NeedData:
        pass

# FIXME: is not optimal parse everything all the time. We should handle sessions
def resolve_socks_proxy(sport, options):
    pcap_path = options['pcap_path']
    pcap_file = open(pcap_path)
    pcap=dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except dpkt.dpkt.NeedData:
            continue
        ip=eth.data
        if type(ip.data) == dpkt.tcp.TCP or type(ip.data) == dpkt.udp.UDP:
            tcp=ip.data
            if tcp.dport == sport:
                # IMPORTANT: This is not a bug, we recover src as dst
                res = { 'dport' : tcp.sport, 'dst': socket.inet_ntoa(ip.src) }
                return res

def perform_check(buf, options):
    rules = options['rules']
    socks_proxy = options['socks_proxy']
    pcap_path = options['pcap_path']

    protocol_details = detect_protocol(buf, options)
    if protocol_details == None:
        return None
    if socks_proxy:
        try:
            socks_details = resolve_socks_proxy(protocol_details['sport'], options)
            protocol_details['dport'] = socks_details['dport']
            protocol_details['dst'] = socks_details['dst']
        except TypeError:
            return None
    return protocol_details

def get_rules():
    rules = yara.compile(filepath=os.path.dirname(__file__)+ os.sep + 'rules/index.yar')
    return rules

def analyze_pcap(options):
    pcap_path = options['pcap_path']
    pcap_file = open(pcap_path)
    try:
        pcap=dpkt.pcap.Reader(pcap_file)
    except dpkt.dpkt.NeedData:
        return

    for ts, buf in pcap:
        results = perform_check(buf, options )
        if results is not None:
            print results

def analyze_interface(options):
    iface = options['iface']
    cap=pcapy.open_live(iface,100000,1,0)
    (header,payload)=cap.next()
    buf = str(payload)
    while header:
        perform_check(buf, options)
        # i need to know whether it is a tcp or  a udp packet here!!!
        (header,payload)=cap.next()