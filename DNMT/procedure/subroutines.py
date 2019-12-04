#!/usr/bin/env python3

import random, re, socket,time,sys
import subprocess,platform
import netmiko
from pysnmp.hlapi import *


class SubRoutines:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = [] #may not need this
        self.cmdargs = cmdargs
        self.config = config



####################
###SNMP COMMANDS####
####################

    def snmp_set(self, ipaddr, *args):
        errorIndication, errorStatus, errorIndex, varBinds = next(
            setCmd(SnmpEngine(),
                   CommunityData(self.config.rw),
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

    def snmp_get(self,  ipaddr, *args):
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(self.config.rw),
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


    def snmp_walk(self,  ipaddr, *args):
        snmpList = []
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(),
            CommunityData(self.config.ro),UdpTransportTarget((ipaddr, 161)), ContextData(),
                                                                            *args, lexicographicMode=False):
            if errorIndication:
                print(errorIndication, file=sys.stderr)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                      file=sys.stderr)
                break
            else:
                snmpList.append(varBinds[0])

        return snmpList


    ####################
    ####SSH COMMANDS####
    ####################
    def create_connection(self,ipaddr):
        if 'verbose' in self.cmdargs and self.cmdargs.verbose:
            print('------- CONNECTING to switch {}-------'.format(ipaddr))

        # Switch Parameters
        cisco_sw = {
            'device_type': 'cisco_ios',
            #'ip': self.cmdargs.ipaddr,
            'ip': ipaddr,
            'username': self.config.username,
            'password': self.config.password,
            'secret': self.config.enable_pw,
            'port': 22,
            'verbose': False,
        }
        # SSH Connection
        net_connect = netmiko.ConnectHandler(**cisco_sw)
        return net_connect
    ####################
    ##GENERAL COMMANDS##
    ####################
    # Name: verbose_printer
    # Input:
    #   cmdargs (holder for cmdargs. This may be replaced by having global vars in it)
    #      -This variable will be checked for the verbose key, and check if it is true
    #   *printvar
    #      -This variable(s) will allow the function to be passed two vars, 1 for what to print if verbose,
    #      and 1 to print if not.
    # verbose printer currently is passed a command line argument variable (cmdargs) and 1-2 strings to print
    # the 1st string is what to print if verbose, the second is what to print if not.
    # printvar accepts a variable number of values in case nothing will be printed for not verbose
    # verbose printer will return True if verbose, and false if not (redundant?)
    def verbose_printer(self,*printvar):
        # if in verbose mode, print the first printvar variable and return that it is in verbose mode
        if 'verbose' in self.cmdargs and self.cmdargs.verbose:
            print(printvar[0])
            return True
        # if in verbose mode, print the first printvar variable
        else:
            if len(printvar) > 1:
                print(printvar[1])
            return False

    def ping_check(self, sHost):
        try:
            output = subprocess.check_output(
                "ping -{} 1 {}".format('n' if platform.system().lower() == "windows" else 'c', sHost), shell=True)
        except Exception as e:
            return False
        return True
