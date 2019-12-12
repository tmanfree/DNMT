#!/usr/bin/env python3

import random, re, socket,time,sys
import subprocess,platform
import netmiko
from pysnmp.hlapi import *

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902


class SubRoutines:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = [] #may not need this
        self.cmdargs = cmdargs
        self.config = config



####################
###SNMP COMMANDS####
####################

    ###BASE SNMP COMMANDS####
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

    ###ADVANCED SNMP COMMANDS####
    #assumes getting infor in 1/0/10 format
    def snmp_get_interface_id(self, ipaddr, interface):
        intId = 0  # intitalize as 0 as not found
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.31.1.1.1.1')))
        #'1.3.6.1.2.1.2.2.1.2')))

        for varBind in varBinds:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            oidId = oidTuple[len(oidTuple) - 1]
            if (varBind._ObjectType__args[1]._value.decode("utf-8").endswith(interface)):
                intId = oidId
        return intId

    def snmp_get_full_interface(self, ipaddr, intId):
        oidstring = '1.3.6.1.2.1.2.2.1.2.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        fullInt = varBind[0]._ObjectType__args[1]._value

        return fullInt.decode("utf-8")

    def snmp_get_interface_vlan(self, ipaddr, intId):
        oidstring = '1.3.6.1.4.1.9.9.68.1.2.2.1.2.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        currentVlan = varBind[0]._ObjectType__args[1]._value

        return currentVlan

    def snmp_get_interface_description(self, ipaddr, intId):
        oidstring = '1.3.6.1.2.1.31.1.1.1.18.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceDescription = varBind[0]._ObjectType__args[1]._value

        return interfaceDescription.decode("utf-8")

    def snmp_set_interface_vlan(self, ipaddr, intId, vlan):
        oidstring = '1.3.6.1.4.1.9.9.68.1.2.2.1.2.{}'.format(intId)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(vlan)))

    def snmp_reset_interface(self,ipaddr,intId):
        oidstring = '1.3.6.1.2.1.2.2.1.7.{}'.format(intId)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(2)))
        time.sleep(2)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(1)))

    def snmp_vlan_grab(self, ipaddr):

        oidstring = '1.3.6.1.4.1.9.9.46.1.3.1.1.4.{}'.format('1')
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        vlansToIgnore = [1002, 1003, 1004, 1005]  # declare what vlans we will ignore.
        vlanList = []  # intitalize a blank list


        for varBind in varBinds:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            vlanId = oidTuple[len(oidTuple) - 1]
            if (vlanId not in vlansToIgnore):
                vlanList.append({'ID': vlanId, "Name": varBind._ObjectType__args[1]._value})

        ##if in verbose mode
        # for vlan in vlanList:
        #     print("Vlan ID:{} Vlan Name:{}".format(vlan["ID"],vlan["Name"].decode("utf-8")))
        return vlanList


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
