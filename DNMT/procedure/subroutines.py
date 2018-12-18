#!/usr/bin/env python3

from netmiko import ConnectHandler
import random
import re
import socket
import time
from pysnmp.hlapi import *
import sys





#def snmp_set(config,ipaddr,oidtup,newval,*args):
def snmp_set(config, ipaddr,*args):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        setCmd(SnmpEngine(),
               CommunityData(config.rw),
               UdpTransportTarget((ipaddr, 161)),
               ContextData(),
               *args)
    )
    if errorIndication:  # check for errors
        print(errorIndication)
    elif errorStatus:  # error status (confirm this)
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        #success
        return True

def snmp_get(config, ipaddr, *args):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(config.rw),
               UdpTransportTarget((ipaddr, 161)),
               ContextData(),
               *args)
    )
    if errorIndication:  # check for errors
        print(errorIndication)
    elif errorStatus:  # error status (confirm this)
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        # success
        return varBinds
