#!/usr/bin/env python3

from netmiko import ConnectHandler
import random
import re
import socket
import time
import sys
from pysnmp.hlapi import *





####################
###SNMP COMMANDS####
####################

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

####################
####SSH COMMANDS####
####################
def create_connection(cmdargs,config):
    if 'verbose' in cmdargs and cmdargs.verbose:
        print('------- CONNECTING to switch {}-------'.format(cmdargs.ipaddr))

    # Switch Parameters
    cisco_sw = {
        'device_type': 'cisco_ios',
        'ip': cmdargs.ipaddr,
        'username': config.username,
        'password': config.password,
        'port': 22,
        'verbose': False,
    }
    # SSH Connection
    net_connect = netmiko.ConnectHandler(**cisco_sw)
    return net_connect
####################
##GENERAL COMMANDS##
####################

# verbose printer currently is passed a command line argument variable (cmdargs) and 1-2 strings to print
# the 1st string is what to print if verbose, the second is what to print if not.
# printvar accepts a variable number of values in case nothing will be printed for not verbose
# verbose printer will return True if verbose, and false if not (redundant?)
def verbose_printer(cmdargs,*printvar):
    if 'verbose' in cmdargs and cmdargs.verbose:
        print(printvar[0])
        return True
    else:
        if len(printvar) > 1:
            print(printvar[1])
        return False
