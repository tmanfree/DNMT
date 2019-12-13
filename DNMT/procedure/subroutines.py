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
    # Name: snmp_get_interface_id
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #   interface (string)
    #      -The interface to grab the ID of (Currently assumes the straight number format ( X/X/X or X/X) or GiX/X
    # Return:
    #  interfaceDescription (a string of the interface description)
    # Summary:
    #   grabs the interface id of a supplied interface.
    #   currently using 1.3.6.1.2.1.31.1.1.1.1, OiD could be updated to 1.3.6.1.2.1.2.2.1.2 for full name checking
    #     (ie GigabitEthernet X/X)
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

    # Name: snmp_get_full_interface
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #   intId (string)
    #      -The id of the interface to set
    # Return:
    #  fullInt (a string of the full interface name)
    # Summary:
    #   grabs the interface name
    def snmp_get_full_interface(self, ipaddr, intId):
        oidstring = '1.3.6.1.2.1.2.2.1.2.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        fullInt = varBind[0]._ObjectType__args[1]._value

        return fullInt.decode("utf-8")

    # Name: snmp_get_interface_vlan
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #   intId (string)
    #      -The id of the interface to set
    # Return:
    #  currentVlan (a string of the current vlan on a port)
    # Summary:
    #   grabs the assigned vlan of an interface
    def snmp_get_interface_vlan(self, ipaddr, intId):
        oidstring = '1.3.6.1.4.1.9.9.68.1.2.2.1.2.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        currentVlan = varBind[0]._ObjectType__args[1]._value

        return currentVlan

    # Name: snmp_get_interface_description
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #   intId (string)
    #      -The id of the interface to set
    # Return:
    #  interfaceDescription (a string of the interface description)
    # Summary:
    #   grabs the description of an interface
    def snmp_get_interface_description(self, ipaddr, intId):
        oidstring = '1.3.6.1.2.1.31.1.1.1.18.{}'.format(intId)
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceDescription = varBind[0]._ObjectType__args[1]._value

        return interfaceDescription.decode("utf-8")

    # Name: snmp_set_interface_vlan
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #   intId (string)
    #      -The id of the interface to set
    #   vlan (string)
    #      -The vlan to set the interface to
    # Return:
    #   none
    # Summary:
    #   Sets the specified interface to the specified vlan
    def snmp_set_interface_vlan(self, ipaddr, intId, vlan):
        oidstring = '1.3.6.1.4.1.9.9.68.1.2.2.1.2.{}'.format(intId)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(vlan)))

    # Name: snmp_reset_interface
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #   intId (string)
    #      -The id of the interface to reset
    # Return:
    #   none
    # Summary:
    #   Shuts down the specified interface, then re-enables it after 2 seconds
    def snmp_reset_interface(self,ipaddr,intId):
        oidstring = '1.3.6.1.2.1.2.2.1.7.{}'.format(intId)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(2)))
        time.sleep(2)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(1)))

    # Name: snmp_vlan_grab
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #   vlanList (list of vlans from switch)
    # Summary:
    #   Grabs list of vlans from 1.3.6.1.4.1.9.9.46.1.3.1.1.4.1
    #   currently ignores vlan 1002 - 1005 as they are defaults on cisco
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

        # Name: snmp_port_poe_alloc_list
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #   vlanList (list of vlans from switch)
        # Summary:
        #   Grabs list of ports 1.3.6.1.4.1.9.9.402.1.2.1.7
        #   currently ignores vlan 1002 - 1005 as they are defaults on cisco
    def snmp_port_poe_alloc_list(self, ipaddr):

        oidstring = '1.3.6.1.4.1.9.9.402.1.2.1.7.1'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        vlansToIgnore = [1002, 1003, 1004, 1005]  # declare what vlans we will ignore.
        intList = []  # intitalize a blank list

        for varBind in varBinds:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            vlanId = oidTuple[len(oidTuple) - 1]
            # if (vlanId not in vlansToIgnore):
            intList.append({'Port': vlanId, "Power": varBind._ObjectType__args[1]._value})

        return intList


    ####################
    ####SSH COMMANDS####
    ####################

    # Name: create_connection
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to connect to
    # Return:
    #   net_connect (connection handler)
    # Summary:
    #   Sets up a connection to the provided ip address. Currently setup to connect to cisco switches
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
    # Summary:
    #   verbose printer currently is passed a command line argument variable (cmdargs) and 1-2 strings to print
    #   the 1st string is what to print if verbose, the second is what to print if not.
    #   printvar accepts a variable number of values in case nothing will be printed for not verbose
    #   verbose printer will return True if verbose, and false if not (redundant?)
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

    # Name: ping_check
    # Input:
    #   host (string)
    #      -The ipaddress/hostname to ping.
    # Return:
    #   true if pingable, false if not
    # Summary:
    #   function trys to ping the provided host and returns boolean success
    def ping_check(self, sHost):
        try:
            output = subprocess.check_output(
                "ping -{} 1 {}".format('n' if platform.system().lower() == "windows" else 'c', sHost), shell=True)
        except Exception as e:
            return False
        return True

    # Name: regex_parser_var0
    # Input:
    #   regex (raw string)
    #      -This variable will contains the regex expression to use.
    #   input (string)
    #      -This variable contains the string to apply the regex search to.
    # Return:
    #   matched string or N/A if nothing is found
    # Summary:
    #   regex_parser_var0 adds some error handling to the regex searching functions. returning a "N/A" default if
    #       nothing is found
    def regex_parser_var0 (self,regex, input):
        findval = re.findall(regex, input, re.MULTILINE);
        if len(findval) > 0:
            return findval[0];
        else:
            return "N/A"