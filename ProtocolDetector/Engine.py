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
          return matches
    except AttributeError:
        print 'DEBUG: No payload'