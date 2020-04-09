#!/usr/bin/env python3

import random, re, socket,time,sys
import subprocess,platform,datetime
import netmiko
from pysnmp.hlapi import *

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

from DNMT.procedure.switchstruct import StackStruct


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
                   CommunityData(self.config.ro),
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

    def vlan_at_snmp_walk(self,  ipaddr, vlanid, *args):
        snmpList = []
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(),
            CommunityData(self.config.ro+"@"+str(vlanid)),UdpTransportTarget((ipaddr, 161)), ContextData(),
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

        # Name: snmp_get_vendor_string
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  a string saying HP, Cisco or Unknown (Change this to an int to use a switch?)
        # Summary:
        #   grabs the vendor string and checks if HP or Cisco is in it, could parse for switch model?

    def snmp_get_vendor_string(self, ipaddr):
        oidstring = '1.3.6.1.2.1.1.1.0'
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        if varBind is not None:
            vendorString = varBind[0]._ObjectType__args[1]._value.decode("utf-8")
            if (re.match("Cisco", vendorString)):
                vendor = "Cisco"
            elif (re.match("HP", vendorString) or re.match("ProCurve", vendorString) ):
                vendor = "HP"
            elif (re.match("Dell", vendorString)):
                vendor="Dell"
            elif (re.match("Neyland", vendorString)): # Ancient arts dells
                vendor = "Ancient Dell"
            else:
                vendor = "Unknown"
        else:
            vendor = "None Found"

        return vendor

        # Name: snmp_get_hostname_string
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  a string of the hostname
        # Summary:
        #   grabs the system name and returns it

    def snmp_get_hostname(self, ipaddr):
        # oidstring = '1.3.6.1.4.1.9.2.1.3.0'
        oidstring = '1.3.6.1.2.1.1.5.0'
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        hostname=""
        if varBind is not None:
            hostname = varBind[0]._ObjectType__args[1]._value.decode("utf-8")


        return hostname

        # Name: snmp_get_crc_errors_by_id
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        #   intId (string)
        #      -The interfaceID to grab the info for
        # Return:
        #  (int)crc errors for supplied port
        # Summary:
        #   grabs the crc errors for a port

    def snmp_get_crc_errors_by_id(self, ipaddr, intId):
        oidstring = '1.3.6.1.4.1.9.2.2.1.1.12.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceErrors = varBind[0]._ObjectType__args[1]._value

        return interfaceErrors

        # Name: snmp_get_input_errors_by_id
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        #   intId (string)
        #      -The interfaceID to grab the info for
        # Return:
        #  (int)output errors for supplied port
        # Summary:
        #   grabs the output errors for a port

    def snmp_get_input_errors_by_id(self, ipaddr,intId):
        oidstring = '1.3.6.1.2.1.2.2.1.14.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceErrors = varBind[0]._ObjectType__args[1]._value

        return interfaceErrors

        # Name: snmp_get_output_errors_by_id
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        #   intId (string)
        #      -The interfaceID to grab the info for
        # Return:
        #  (int) input errors for supplied port
        # Summary:
        #   grabs the input errors for a port

    def snmp_get_output_errors_by_id(self, ipaddr,intId):
        oidstring = '1.3.6.1.2.1.2.2.1.20.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceErrors = varBind[0]._ObjectType__args[1]._value

        return interfaceErrors




    # Name: snmp_get_interface_id_bulk
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #  interfaceDescriptions (a string of the interface description)
    # Summary:
    #   returns all interface ids
    def snmp_get_interface_id_bulk(self, ipaddr,vendor):
        intId = 0  # intitalize as 0 as not found
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.31.1.1.1.1')))
        returnList = []


        for varBind in varBinds:
            portname = varBind._ObjectType__args[1]._value.decode("utf-8")
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            oidId = oidTuple[len(oidTuple) - 1]
            # if (re.match(r"^\w{2}[1-9](/\d)?/\d+", portname)):
            if vendor == "Cisco" or vendor == "Dell":
                if(re.match(r"^\w{2}[0-9](/\d)?/\d+", portname )):
                    switchnum = self.regex_parser_varx(r"^\w{2}([0-9])(?:/(\d))?/(\d+)", portname)
                    if (len(switchnum) == 3): #verify that return isn't borked, should get 3 length tuple
                        # if((switchnum[2] != 0) and (switchnum[1] != '')): # get rid of 0/0 interface
                        if ((int(switchnum[2]) != 0) and (switchnum[1] != '')):  # get rid of 0/0 interface
                            returnList.append(
                                {'Switch': int(switchnum[0]), 'Module': int(switchnum[1]), 'Port': int(switchnum[2]),
                                 'PortName': portname,
                                     'Id': oidId})
                        elif ((int(switchnum[2]) != 0) and (switchnum[1] == '')):
                            returnList.append({'Switch': 1, 'Module': int(switchnum[0]), 'Port': int(switchnum[2]),
                                               'PortName': portname, 'Id': oidId})
            elif vendor == "HP":
                if (re.match(r"^(\d+)$", portname)):
                    returnList.append({'Switch': 1, 'Module': 0, 'Port': int(portname),
                                           'PortName': portname, 'Id': oidId})
            elif vendor == "Ancient Dell":
                if (re.match(r"^g(\d+)$", portname)):
                    interface = self.regex_parser_var0(r"^g(\d+)$", portname)
                    returnList.append({'Switch': 1, 'Module': 0, 'Port': int(interface),
                                       'PortName': portname, 'Id': oidId})


                # switchnum = self.regex_parser_varx(r"^\w{2}([1-9])((/\d))?/(\d+)", portname, 3)
                # if(re.match(r"^\w{2}[1-9](/\d)?/\d+", portname )):

        return returnList

        # Name: snmp_get_switch_id_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        #   vendor (string)
        #      -The vendor type, HP,Cisco,Unknown
        # Return:
        #  returnList (a list of switch IDs to get model number/serial number info)
        # Summary:
        #   returns all switch IDs

    def snmp_get_switch_id_bulk(self, ipaddr, vendor):
        intId = 0  # intitalize as 0 as not found
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.47.1.1.1.1.7')))
        returnList = []
        if vendor == "Cisco":
            for varBind in varBinds:
                varName = varBind._ObjectType__args[1]._value.decode("utf-8")
                oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
                oidId = oidTuple[len(oidTuple) - 1]
                # if (re.match(r"^\w{2}[1-9](/\d)?/\d+", portname)):

                if (re.match(r"^Switch [0-9]$", varName)):
                    switchnum = self.regex_parser_var0(r"^Switch ([0-9])?", varName)
                    if switchnum is not None:
                        returnList.append({'Switch': int(switchnum), 'Id': oidId})
                elif ((re.match(r"^[0-9]$", varName)) and oidId in [1001,2001,3001,4001,5001,6001,7001,8001,9001]): #Added Fix for 3750X format
                    returnList.append({'Switch': int(varName), 'Id': oidId})
                # elif (re.match("Linecard\(slot \d\)",varName)): #4500 creates a switches for each slot, and a module too
                #     switchnum = self.regex_parser_var0(r"^Linecard\(slot ([0-9])\)?", varName)
                #     if switchnum is not None:
                #         returnList.append({'Switch': int(switchnum), 'Id': oidId})
        elif vendor =="HP" or vendor == "Ancient Dell":
            returnList.append({'Switch': 1, 'Id': 1}) #Currently defaulting to using id of 1
        elif vendor == "Dell":
            for varBind in varBinds:
                varName = varBind._ObjectType__args[1]._value.decode("utf-8")
                oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
                oidId = oidTuple[len(oidTuple) - 1]
                # if (re.match(r"^\w{2}[1-9](/\d)?/\d+", portname)):

                if (re.match(r"^Unit [0-9]$", varName)):
                    switchnum = self.regex_parser_var0(r"^Unit ([0-9])?", varName)
                    if switchnum is not None:
                        returnList.append({'Switch': int(switchnum), 'Id': oidId})


        return returnList

        # Name: snmp_get_serial_number
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        #   intId (string)
        #      -The id of the switch
        # Return:
        #  serialNum (serial number in string format)
        # Summary:
        #   grabs the switch serial number

    def snmp_get_serial_number(self, ipaddr, intId):
        oidstring = '1.3.6.1.2.1.47.1.1.1.1.11.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        serialNum = varBind[0]._ObjectType__args[1]._value

        return serialNum.decode("utf-8")

        # Name: snmp_get_serial_number_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        #   intId (string)
        #      -The id of the switch
        # Return:
        #  serialNum (serial number in string format)
        # Summary:
        #   grabs the switch serial number

    def snmp_get_serial_number_bulk(self, ipaddr):
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.47.1.1.1.1.11')))
        returnList = []

        for varBind in varBinds:
            varName = varBind._ObjectType__args[1]._value.decode("utf-8")
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            oidId = oidTuple[len(oidTuple) - 1]
            # if (re.match(r"^\w{2}[1-9](/\d)?/\d+", portname)):
            # if (varName != ""):
            returnList.append({'Serial': varName, 'Id': oidId})

        return returnList

      # Name: snmp_get_model
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        #   intId (string)
        #      -The id of the switch
        # Return:
        #  model (model type in string format)
        # Summary:
        #   grabs the switch model type

    def snmp_get_model(self, ipaddr, intId):
        oidstring = '1.3.6.1.2.1.47.1.1.1.1.13.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        model = varBind[0]._ObjectType__args[1]._value

        return model.decode("utf-8")

      # Name: snmp_get_software
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        #   intId (string)
        #      -The id of the switch
        # Return:
        #  softwareVersion (software version in string format)
        # Summary:
        #   grabs the switch software version

    def snmp_get_software(self, ipaddr, intId):
        oidstring = '1.3.6.1.2.1.47.1.1.1.1.10.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        softwareVersion = varBind[0]._ObjectType__args[1]._value

        return softwareVersion.decode("utf-8")


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


    # Name: snmp_get_interface_vlan_bulk
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #   intId (string)
    #      -The id of the interface to set
    # Return:
    #  currentVlan (a string of the current vlan on a port)
    # Summary:
    #   grabs all interface vlan assignments
    def snmp_get_interface_vlan_bulk(self, ipaddr,vendor):
        interfaceVlanList = []
        if vendor == "Cisco":
            oidstring = '1.3.6.1.4.1.9.9.68.1.2.2.1.2'
            varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))

            for varBind in varBinds:
                interfaceVlan = varBind._ObjectType__args[1]._value
                oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
                intId = oidTuple[len(oidTuple) - 1]
                interfaceVlanList.append({'Id':intId,'Vlan':interfaceVlan})
        elif vendor == "HP" or vendor == "Dell" or vendor == "Ancient Dell":

            oidstring = '1.3.6.1.2.1.17.7.1.4.3.1.4'
            varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))

            for varBind in varBinds:
                interfaceVlan = varBind._ObjectType__args[1]._value
                oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
                intId = oidTuple[len(oidTuple) - 1]

                binaryArray = [self.access_bit(interfaceVlan,i) for i in range(len(interfaceVlan)*8)]

                for idx, val in enumerate(binaryArray):
                    if val ==1:
                        interfaceVlanList.append({'Id': idx+1, 'Vlan': intId})



        return interfaceVlanList

    def access_bit(self, data, num):
        base = int(num // 8) # which byte
        shift = int(num % 8) # which bit

        return (data[base] & (128 >> shift)) >> 7-shift
        # This will give the binary in opposite order 1-128 instead of 128->1
        # if sys.byteorder == "little":
        #     return (data[base] & (1 << shift)) >> shift



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

    # Name: snmp_set_interface_description
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #   intId (string)
    #      -The id of the interface to set
    #   dssc (string)
    #      -The description to assign to the interface
    # Return:
    #   none
    # Summary:
    #   Sets the description for the specified interface
    def snmp_set_interface_description(self, ipaddr, intId, desc):
        oidstring = '1.3.6.1.2.1.31.1.1.1.18.{}'.format(intId)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), OctetString(desc)))
        #self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(5)))


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

    # Name: snmp_get_vlan_database
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #   vlanList (list of vlans from switch)
    # Summary:
    #   Grabs list of vlans from 1.3.6.1.4.1.9.9.46.1.3.1.1.4.1
    #   currently ignores vlan 1002 - 1005 as they are defaults on cisco
    def snmp_get_vlan_database(self, ipaddr):

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

    #     # Name: snmp_get_vendor
    #     # Input:
    #     #   ipaddr (string)
    #     #      -The ipaddress/hostname to grab info from
    #     # Return:
    #     #  interfaceDescription (a string of the interface description)
    #     # Summary:
    #     #  Currently Defunct
    #
    # def snmp_get_vendor(self, ipaddr):
    #     oidstring = '.1.3.6.1.2.1.1.1.0'
    #     varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)))
    #     interfaceDescription = varBind[0]._ObjectType__args[1]._value
    #
    #     return interfaceDescription.decode("utf-8")



    ###CUSTOM SNMP COMMANDS####
    #Returns are more tailored to specific functions
        # Name: snmp_get_port_poe_alloc_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #   intList (list of ports)
        # Summary:
        #   Returns a list of poe allocation in the format {Switch:X,Port:X,"Power:X"}
        # OID NOT VALID FOR DELL
    def snmp_get_port_poe_alloc_bulk(self, ipaddr):

        oidstring = '1.3.6.1.4.1.9.9.402.1.2.1.7'
        # oidstring = '1.3.6.1.4.1.9.9.402.1.2.1.7.1'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        intList = []  # intitalize a blank list

        for varBind in varBinds:
            switchNumber = varBind._ObjectType__args[0]._ObjectIdentity__oid._value[len(varBind._ObjectType__args[0]._ObjectIdentity__oid._value)-2]
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            portId = oidTuple[len(oidTuple) - 1]
            intList.append({'Switch':switchNumber,'Port': portId, "Power": varBind._ObjectType__args[1]._value})

        return intList

        # Name: snmp_get_port_activity_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #   interfaceList (list of ports)
        # Summary:
        #   Returns a list of active ports in structure {Switch:X,Port:X}
        #   Has an issue with uplinks of X/1/X currently

    def snmp_get_port_activity_bulk(self, ipaddr):

        oidstring = '1.3.6.1.2.1.2.2.1.8'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        intList = []  # intitalize a blank list

        for varBind in varBinds:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            vlanId = oidTuple[len(oidTuple) - 1]
            intList.append({'Id': vlanId, "Status": varBind._ObjectType__args[1]._value})


        return intList

    # Name: snmp_get_interface_description_bulk
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #  interfaceDescriptionList (a list of strings of the interface descriptions)
    # Summary:
    #   grabs the description of all physical interfaces
    def snmp_get_interface_description_bulk(self, ipaddr):
        # oidstring = '1.3.6.1.2.1.31.1.1.1.1'
        oidstring = '1.3.6.1.2.1.31.1.1.1.18'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceDescriptionList = []

        for varBind in varBinds:
            interfaceDescription = varBind._ObjectType__args[1]._value.decode("utf-8")
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceDescriptionList.append({'Id':intId,'Description':interfaceDescription})

            # intList.append({'Switch': switchNumber, 'Port': vlanId, "Power": varBind._ObjectType__args[1]._value})

        return interfaceDescriptionList

        # Name: snmp_get_interface_trunking_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  interfaceTrunkingList (a list of strings of the interface trunk modes)
        # Summary:
        #   grabs the description of all physical interfaces
    def snmp_get_interface_trunking_bulk(self, ipaddr, vendor):
        interfaceTrunkingList = []
        if vendor == "Cisco":
            oidstring = '1.3.6.1.4.1.9.9.46.1.6.1.1.14'
            varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))


            for varBind in varBinds:
                # TrunkMode = varBind._ObjectType__args[1]._value.decode("utf-8")
                # if '/' in interfaceDescription:
                oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
                intId = oidTuple[len(oidTuple) - 1]
                interfaceTrunkingList.append({'Id': intId, 'TrunkMode': varBind._ObjectType__args[1]._value})

                # intList.append({'Switch': switchNumber, 'Port': vlanId, "Power": varBind._ObjectType__args[1]._value})

        return interfaceTrunkingList

        # Name: snmp_get_cdp_type_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  cdp neighbour list
        # Summary:
        #   grabs the cdp object type that is connected to each interface
    def snmp_get_cdp_type_bulk(self, ipaddr):
        # oidstring = '1.3.6.1.2.1.31.1.1.1.1'
        oidstring = '1.3.6.1.4.1.9.9.23.1.2.1.1.8'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceCdpList = []

        for varBind in varBinds:
            interfaceCdp = varBind._ObjectType__args[1]._value.decode("utf-8")
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 2]
            interfaceCdpList.append({'Id': intId, 'Cdp': interfaceCdp})

        return interfaceCdpList

        # Name: snmp_get_voice_vlan_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  cdp neighbour list
        # Summary:
        #   grabs the voice vlan that is connected to each interface
    def snmp_get_voice_vlan_bulk(self, ipaddr):
        oidstring = '1.3.6.1.4.1.9.9.68.1.5.1.1.1'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceVlanList = []

        for varBind in varBinds:
            interfaceVlan = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceVlanList.append({'Id': intId, 'Vlan': interfaceVlan})

        return interfaceVlanList


        # Name: snmp_get_input_errors_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  input errors list
        # Summary:
        #   grabs the a list of input errors
    def snmp_get_input_errors_bulk(self, ipaddr):
        oidstring = '1.3.6.1.2.1.2.2.1.14 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceErrorist = []

        for varBind in varBinds:
            interfaceError = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceErrorist.append({'Id': intId, 'Errors': interfaceError})

        return interfaceErrorist

        # Name: snmp_get_output_errors_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  input errors list
        # Summary:
        #   grabs the a list of input errors
    def snmp_get_output_errors_bulk(self, ipaddr):
        oidstring = '1.3.6.1.2.1.2.2.1.20 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceErrorist = []

        for varBind in varBinds:
            interfaceError = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceErrorist.append({'Id': intId, 'Errors': interfaceError})

        return interfaceErrorist

    # Name: snmp_get_input_counters_bulk
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #  input counters list
    # Summary:
    #   grabs the a list of input counters (adds ifinOctets and ifinUcast together)
    def snmp_get_input_counters_bulk(self, ipaddr):
        oidstring = '1.3.6.1.2.1.2.2.1.10 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceCounterList = []

        for varBind in varBinds:
            interfaceCounters = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceCounterList.append({'Id': intId, 'Counters': interfaceCounters})

        oidstring = '1.3.6.1.2.1.2.2.1.11 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))

        for varBind in varBinds:
            interfaceCounters = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            test = [entry for entry in interfaceCounterList if entry['Id'] == intId]
            test[0]['Counters'] += interfaceCounters #This works as test is a reference to the list entry!


        return interfaceCounterList

    # Name: snmp_get_output_counters_bulk
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #  output counters list
    # Summary:
    #   grabs the a list of out counters (adds ifoutOctets and ifoutUcast together)
    def snmp_get_output_counters_bulk(self, ipaddr):
        oidstring = '1.3.6.1.2.1.2.2.1.16 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        interfaceCounterList = []

        for varBind in varBinds:
            interfaceCounters = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceCounterList.append({'Id': intId, 'Counters': interfaceCounters})

        oidstring = '1.3.6.1.2.1.2.2.1.17 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))

        for varBind in varBinds:
            interfaceCounters = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            test = [entry for entry in interfaceCounterList if entry['Id'] == intId]
            test[0]['Counters'] += interfaceCounters  # This works as test is a reference to the list entry!

        return interfaceCounterList

        # Name: snmp_get_mac_table_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  mac_address_list
        # Summary:
        #   grabs the a list of mac addresses on the switch. Time intensive procedure.
    def snmp_get_mac_table_bulk(self, ipaddr):

        oidstring = '1.3.6.1.2.1.17.4.3.1'
        macList=[]
        vlanList = self.snmp_get_vlan_database(ipaddr)

        for vlan in vlanList:
            #Return should always be a factor of 3. X=MAC, X+1=Port, X+2=status
            varBinds = self.vlan_at_snmp_walk(ipaddr,vlan['ID'],ObjectType(ObjectIdentity(oidstring)))
            i = 0
            while ( i < len(varBinds)/3):
                macList.append({"MAC": varBinds[i]._ObjectType__args[1]._value,
                                "InterfaceID": varBinds[i + int(len(varBinds)/3)]._ObjectType__args[1]._value,
                                "Status": varBinds[i + int((len(varBinds)/3)*2)]._ObjectType__args[1]._value,
                                "Vlan": vlan['ID']})
                i += 1


        return macList

        # Name: snmp_get_switch_data_full
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  a data structure (a list of strings of the interface descriptions)
        # Summary:
        #   grabs information from the switch to put in a datastructure


    def snmp_get_switch_data_full(self, ipaddr):
        # test = self.snmp_get_switch_id_bulk(ipaddr)

        vendor = self.snmp_get_vendor_string(ipaddr)
        switchStruct = StackStruct(ipaddr, vendor)
        if vendor != "None Found":
            switchStruct.hostname = self.snmp_get_hostname(ipaddr)

            for switch in self.snmp_get_switch_id_bulk(ipaddr,vendor):
                if (switchStruct.getSwitch(switch['Switch']) is None):
                    switchStruct.addSwitch(switch['Switch'])
                switchStruct.getSwitch(switch['Switch']).id = switch['Id']

            for switch in switchStruct.switches: #individual calls for this seem to be resolving faster than a bulk
                switch.serialnumber=self.snmp_get_serial_number(ipaddr,switch.id)
                switch.model = self.snmp_get_model(ipaddr,switch.id)
                switch.version = self.snmp_get_software(ipaddr,switch.id)



            #get interfaces and create them on the structure if they are not there
            for port in self.snmp_get_interface_id_bulk(ipaddr,vendor):
                if (switchStruct.getSwitch(port['Switch']) is None): #Comment out?
                    switchStruct.addSwitch(port['Switch'])  #Comment out?
                if (switchStruct.getSwitch(port['Switch']).getModule(port['Module']) is None):
                    switchStruct.getSwitch(port['Switch']).addModule(port['Module'])
                # if (switchStruct.getSwitch(port['Switch']).getModule(port['Module']).getPort(port['Port']) is None):
                #     switchStruct.getSwitch(port['Switch']).getModule(port['Module']).addPort(port['Port'])
                # switchStruct.getSwitch(port['Switch']).getModule(port['Module']).getPort(port['Port']).portname = port['PortName']
                # switchStruct.getSwitch(port['Switch']).getModule(port['Module']).getPort(port['Port']).intID = port[
                #     'Id']
                if (switchStruct.getPortById(port['Id']) is None):
                    switchStruct.getSwitch(port['Switch']).getModule(port['Module']).addPort(port['Id'])
                switchStruct.getPortById(port['Id']).portname = port['PortName']
                switchStruct.getPortById(port['Id']).portnumber = int(port['Port'])


            #go through power return Not working for Dell
            for port in self.snmp_get_port_poe_alloc_bulk(ipaddr):
                if port is not None:
                    #This doesnt use the interfaceId, the first return should be the base-t result in the event of gi & te
                    #such as 3650 uplink module being 1/0/1 on ten and gi
                    # self.verbose_printer("#####{} poe processing port {}".format(ipaddr,port))
                    poe_offset = 0
                    if "WS-C3560-8PC" in switchStruct.getSwitch(port['Switch']).model: # fix for WS-C3560-8PC switches being offset by 1 for poe (poe 2 is port 1, etc)
                        poe_offset = 1
                    elif "WS-C3560-24P" in switchStruct.getSwitch(port['Switch']).model or "WS-C3560-48P" in switchStruct.getSwitch(port['Switch']).model or "C3560V2" in switchStruct.getSwitch(port['Switch']).model:
                        poe_offset = 2
                    switchport = switchStruct.getSwitch(port['Switch']).getModule(0).getPort(port['Port']-poe_offset)
                    if switchport is not None:
                        switchport.poe = port['Power']
                else:
                    port['Power'] = "N/A" #TODO update this to align with not found verbage
                #hard set using module 0^


            #go through interface returns (includes vlans, so need to map id to port)
            #get port status (2 is up, 1 is down)
            for port in self.snmp_get_port_activity_bulk(ipaddr):
                if port is not None: #ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.status = port['Status']
            #get trunk mode
            for port in self.snmp_get_interface_trunking_bulk(ipaddr,vendor):
                if port is not None: #ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.portmode = port['TrunkMode']
            #Get descriptions
            for port in self.snmp_get_interface_description_bulk(ipaddr):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.description = port['Description']
            # Get Vlans on ports
            for port in self.snmp_get_interface_vlan_bulk(ipaddr,vendor):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.datavlan = port['Vlan']

           # Get CDP information for ports
            for port in self.snmp_get_cdp_type_bulk(ipaddr):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.cdp = port['Cdp']

            # Get input Errors for ports
            for port in self.snmp_get_input_errors_bulk(ipaddr):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.inputerrors = port['Errors']
                        foundport.historicalinputerrors.append((int(datetime.datetime.now().strftime("%Y%m%d%H%M")),port['Errors']))

            # Get output Errors for ports
            for port in self.snmp_get_output_errors_bulk(ipaddr):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.outputerrors = port['Errors']
                        foundport.historicaloutputerrors.append((int(datetime.datetime.now().strftime("%Y%m%d%H%M")),port['Errors']))

            # Get input Counters for ports
            for port in self.snmp_get_input_counters_bulk(ipaddr):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.inputcounters = port['Counters']
                        foundport.historicalinputcounters.append((int(datetime.datetime.now().strftime("%Y%m%d%H%M")),port['Counters']))

            for port in self.snmp_get_output_counters_bulk(ipaddr):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.outputcounters = port['Counters']
                        foundport.historicaloutputcounters.append((int(datetime.datetime.now().strftime("%Y%m%d%H%M")), port['Counters']))

            for port in self.snmp_get_voice_vlan_bulk(ipaddr):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.voicevlan = port['Vlan']

        if len(switchStruct.switches) == 0:
            # self.subs.verbose_printer("No information found for {}".format(ipaddr))
            print("##### {} - No SwitchStruct information found (SNMP issue?) #####".format(ipaddr))

        return switchStruct

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

    #TODO, replace above one with this one below

    # Name: create_connection_vendor
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to connect to
    #   vendor (string)
    #      -The device type:
    #       example(cisco_ios,
    # Return:
    #   net_connect (connection handler)
    # Summary:
    #   Sets up a connection to the provided ip address. Currently setup to connect to cisco switches
    def create_connection_vendor(self, ipaddr, vendor):
        if 'verbose' in self.cmdargs and self.cmdargs.verbose:
            print('------- CONNECTING to switch {}-------'.format(ipaddr))

        # Switch Parameters
        net_sw = {
            'device_type': vendor,
            # 'ip': self.cmdargs.ipaddr,
            'ip': ipaddr,
            'username': self.config.username,
            'password': self.config.password,
            'secret': self.config.enable_pw,
            'port': 22,
            'verbose': False,
        }
        # SSH Connection
        net_connect = netmiko.ConnectHandler(**net_sw)
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
            return None

    # Name: regex_parser_varx
    # Input:
    #   regex (raw string)
    #      -This variable will contains the regex expression to use.
    #   input (string)
    #      -This variable contains the string to apply the regex search to.
    # Return:
    #   matched string or N/A if nothing is found
    # Summary:
    #   regex_parser_varx adds some error handling to the regex searching functions. returning a "N/A" default if
    #       nothing is found
    def regex_parser_varx (self,regex, input):
        findval = re.findall(regex, input, re.MULTILINE);
        if len(findval) > 0 :
            return findval[0]
            # if len(findval[0]) > numMatches:

        else:
            return None