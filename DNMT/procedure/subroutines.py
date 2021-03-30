#!/usr/bin/env python3

import random, re, socket,time,sys,os
import subprocess,platform,datetime
import netmiko
from pysnmp.hlapi import *


from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

#for Emails
import smtplib
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.audio import MIMEAudio
from email import encoders
import mimetypes




#for readable activity files
import zipfile #imports for summary filescompression imports
import pickle,bz2 #imports for statchecks

from DNMT.procedure.switchstruct import StackStruct


class SubRoutines:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = [] #may not need this
        self.cmdargs = cmdargs
        self.config = config
        self.log_path = os.path.abspath(os.path.join(os.sep, 'var', 'log', 'dnmt')) #will be used by statuschecks right now



####################
###SNMP COMMANDS####
####################

    ###BASE SNMP COMMANDS####
    def snmp_set(self, ipaddr, *args, **kwargs):
        self.custom_printer("debug", "## DBG - {} - SNMP GET Trying SNMP V3 {} ##".format(ipaddr, args))
        if kwargs.get('snmpv3_user_string') is None:
            snmpv3_user_string = self.config.snmpv3_rw_user_string
        else:
            snmpv3_user_string = kwargs.get('snmpv3_user_string')

        if kwargs.get('snmpv3_auth_string') is None and len(self.config.snmpv3_rw_auth_string) > 0:
            snmpv3_auth_string = self.config.snmpv3_rw_auth_string
        else:
            snmpv3_auth_string = kwargs.get('snmpv3_auth_string')

        if kwargs.get('snmpv3_priv_string') is None and len(self.config.snmpv3_rw_priv_string) > 0:
            snmpv3_priv_string = self.config.snmpv3_rw_priv_string
        else:
            snmpv3_priv_string = kwargs.get('snmpv3_priv_string')

        snmp_tuple = (SnmpEngine(), UsmUserData(snmpv3_user_string, snmpv3_auth_string, snmpv3_priv_string),
                      UdpTransportTarget((ipaddr, 161)), ContextData(), *args)
        errorIndication, errorStatus, errorIndex, varBinds = next(setCmd(*snmp_tuple))

        if errorIndication is not None:
            self.custom_printer("debug",
                                "## DBG - {} SNMPV3 SET Failed {}, trying V2 ##".format(ipaddr, errorIndication))
            if kwargs.get('rw') is None:
                rw_string = self.config.rw
            else:
                rw_string = kwargs.get('rw')
            snmp_tuple = (SnmpEngine(), CommunityData(rw_string),UdpTransportTarget((ipaddr, 161)), ContextData(), *args)
            errorIndication, errorStatus, errorIndex, varBinds = next(setCmd(*snmp_tuple))
            if errorIndication:  # check for errors
                print("{} - {}".format(ipaddr,errorIndication))
                return False
            elif errorStatus:  # error status (confirm this)
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                return False
            else:
                #success
                self.custom_printer("debug", "## DBG - {} - SNMP SET SUCCESSFUL SNMP V2 {} ##".format(ipaddr, args))
                return True
        else:
            self.custom_printer("debug", "## DBG - {} - SNMP SET SUCCESSFUL SNMP V3 {} ##".format(ipaddr, args))
            return True
    def test_snmpv3(self, ipaddr,oid, *args, **kwargs):
        self.custom_printer("debug", "## DBG - Trying SNMP V3 {} ##".format(ipaddr))
        if kwargs.get('snmpv3_user_string') is None:
            snmpv3_user_string = self.config.snmpv3_ro_user_string
        else:
            snmpv3_user_string = kwargs.get('snmpv3_user_string')

        if kwargs.get('snmpv3_auth_string') is None and len(self.config.snmpv3_ro_auth_string) > 0 :
            snmpv3_auth_string = self.config.snmpv3_ro_auth_string
        else:
            snmpv3_auth_string = kwargs.get('snmpv3_auth_string')

        if kwargs.get('snmpv3_priv_string') is None and len(self.config.snmpv3_ro_priv_string) > 0 :
            snmpv3_priv_string = self.config.snmpv3_ro_priv_string
        else:
            snmpv3_priv_string = kwargs.get('snmpv3_priv_string')

            snmpTuple = (SnmpEngine(),UsmUserData(snmpv3_user_string,snmpv3_auth_string,snmpv3_priv_string), UdpTransportTarget((ipaddr, 161)),ContextData(),ObjectType(ObjectIdentity(oid)))
        snmpList = []
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(*snmpTuple, lexicographicMode=False):
            if errorIndication:
                print("{} - {}".format(ipaddr, errorIndication), file=sys.stderr)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                      file=sys.stderr)
                break
            else:
                snmpList.append(varBinds[0])
            ###


        errorIndication, errorStatus, errorIndex, varBinds = next(getCmd(
            SnmpEngine(),
            UsmUserData(snmpv3_user_string,snmpv3_auth_string,snmpv3_priv_string),
            # UsmUserData(*tupler),
            UdpTransportTarget((ipaddr, 161)),
            ContextData(),
            # ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets', 1))
            ObjectType(ObjectIdentity(oid))
        ))

        if errorIndication is not None:
            self.custom_printer("debug", "## DBG - {} SNMPV3 Failed {}, trying V2 ##".format(ipaddr,errorIndication))
        else: #V3 Successful
            return varBinds





    def snmp_get(self,  ipaddr, *args, **kwargs):
        self.custom_printer("debug", "## DBG - {} - SNMP GET Trying SNMP V3 {} ##".format(ipaddr,args))
        if kwargs.get('snmpv3_user_string') is None:
            snmpv3_user_string = self.config.snmpv3_ro_user_string
        else:
            snmpv3_user_string = kwargs.get('snmpv3_user_string')

        if kwargs.get('snmpv3_auth_string') is None and len(self.config.snmpv3_ro_auth_string) > 0:
            snmpv3_auth_string = self.config.snmpv3_ro_auth_string
        else:
            snmpv3_auth_string = kwargs.get('snmpv3_auth_string')

        if kwargs.get('snmpv3_priv_string') is None and len(self.config.snmpv3_ro_priv_string) > 0:
            snmpv3_priv_string = self.config.snmpv3_ro_priv_string
        else:
            snmpv3_priv_string = kwargs.get('snmpv3_priv_string')


        snmp_tuple = (SnmpEngine(), UsmUserData(snmpv3_user_string, snmpv3_auth_string, snmpv3_priv_string),
                      UdpTransportTarget((ipaddr, 161)), ContextData(), *args)
        errorIndication, errorStatus, errorIndex, varBinds = next(getCmd(*snmp_tuple))

        if errorIndication is not None:
            self.custom_printer("debug", "## DBG - {} SNMPV3 GET Failed {}, trying V2 ##".format(ipaddr, errorIndication))
            if kwargs.get('ro') is None:
                ro_string = self.config.ro
            else:
                ro_string = kwargs.get('ro')
            snmp_tuple = (SnmpEngine(), CommunityData(ro_string), UdpTransportTarget((ipaddr, 161)), ContextData(), *args)
            errorIndication, errorStatus, errorIndex, varBinds = next(getCmd(*snmp_tuple))

            if errorIndication:  # check for errors
                print("{} - {}".format(ipaddr,errorIndication))
            elif errorStatus:  # error status (confirm this)
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            else:
                # success
                self.custom_printer("debug", "## DBG - {} - SNMP GET SUCCESSFUL SNMP V2 {} ##".format(ipaddr, args))
                return varBinds
        else:
            self.custom_printer("debug", "## DBG - {} - SNMP GET SUCCESSFUL SNMP V3 {} ##".format(ipaddr, args))
            return varBinds


    def snmp_walk(self,  ipaddr, *args,**kwargs):
        snmpList = []
        self.custom_printer("debug", "## DBG - {} - SNMP WALK Trying SNMP V3 {} ##".format(ipaddr,args))
        if kwargs.get('snmpv3_user_string') is None:
            snmpv3_user_string = self.config.snmpv3_ro_user_string
        else:
            snmpv3_user_string = kwargs.get('snmpv3_user_string')

        if kwargs.get('snmpv3_auth_string') is None and len(self.config.snmpv3_ro_auth_string) > 0 :
            snmpv3_auth_string = self.config.snmpv3_ro_auth_string
        else:
            snmpv3_auth_string = kwargs.get('snmpv3_auth_string')

        if kwargs.get('snmpv3_priv_string') is None and len(self.config.snmpv3_ro_priv_string) > 0 :
            snmpv3_priv_string = self.config.snmpv3_ro_priv_string
        else:
            snmpv3_priv_string = kwargs.get('snmpv3_priv_string')

            snmp_tuple = (SnmpEngine(),UsmUserData(snmpv3_user_string,snmpv3_auth_string,snmpv3_priv_string), UdpTransportTarget((ipaddr, 161)),ContextData(),*args)
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(*snmp_tuple, lexicographicMode=False):
            if errorIndication:
                print("{} - {}".format(ipaddr,errorIndication), file=sys.stderr)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                      file=sys.stderr)
                break
            else:
                snmpList.append(varBinds[0])
        if errorIndication is not None:
            self.custom_printer("debug", "## DBG - {} SNMPV3 WALK Failed {}, trying V2 ##".format(ipaddr, errorIndication))
            if kwargs.get('ro') is None:
                ro_string = self.config.ro
            else:
                ro_string = kwargs.get('ro')

            snmp_tuple = (SnmpEngine(), CommunityData(ro_string), UdpTransportTarget((ipaddr, 161)), ContextData(), *args)
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(*snmp_tuple, lexicographicMode=False):
                if errorIndication:
                    print("{} - {}".format(ipaddr,errorIndication), file=sys.stderr)
                    break
                elif errorStatus:
                    print('%s at %s' % (errorStatus.prettyPrint(),
                                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                          file=sys.stderr)
                    break
                else:
                    self.custom_printer("debug", "## DBG - {} - SNMP WALK SUCCESSFUL SNMP V2 {} ##".format(ipaddr, args))
                    snmpList.append(varBinds[0])
        else:
            self.custom_printer("debug", "## DBG - {} - SNMP WALK SUCCESSFUL SNMP V3 {} ##".format(ipaddr, args))

        return snmpList

    def vlan_at_snmp_walk(self,  ipaddr, vlanid, *args,**kwargs):
        if kwargs.get('ro') is None:
            ro_string = self.config.ro
        else:
            ro_string = kwargs.get('ro')
        snmpList = []
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(),
            CommunityData(ro_string+"@"+str(vlanid)),UdpTransportTarget((ipaddr, 161)), ContextData(),
                                                                            *args, lexicographicMode=False):
            if errorIndication:
                print("{} - {}".format(ipaddr,errorIndication), file=sys.stderr)
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

    # Name: snmp_save_config
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname of the switch to write-mem on
    # Summary:
    #   Saves the running config to the startup config of a cisco switch
    #     (ie GigabitEthernet X/X)
    def snmp_save_config(self, ipaddr,**kwargs):

        randnum = random.randint(1, 100)
        if (self.snmp_set(ipaddr,
                               ObjectType(ObjectIdentity('CISCO-CONFIG-COPY-MIB', 'ccCopySourceFileType', randnum
                                                         ).addAsn1MibSource('file:///usr/share/snmp',
                                                                            'http://mibs.snmplabs.com/asn1/@mib@'), 4),
                               ObjectType(ObjectIdentity('CISCO-CONFIG-COPY-MIB', 'ccCopyDestFileType', randnum
                                                         ).addAsn1MibSource('file:///usr/share/snmp',
                                                                            'http://mibs.snmplabs.com/asn1/@mib@'), 3),
                               ObjectType(ObjectIdentity('CISCO-CONFIG-COPY-MIB', 'ccCopyEntryRowStatus', randnum
                                                         ).addAsn1MibSource('file:///usr/share/snmp',
                                                                            'http://mibs.snmplabs.com/asn1/@mib@'), 4), rw=kwargs.get('rw')
                               )):

            complete = False
            secs = 0

            while not complete and secs < 30:
                varBinds = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(
                    'CISCO-CONFIG-COPY-MIB', 'ccCopyState', randnum).addAsn1MibSource(
                    'file:///usr/share/snmp',
                    'http://mibs.snmplabs.com/asn1/@mib@')))
                if (varBinds):
                    return_oid, return_value = varBinds[0]
                    return_value = str(return_value)  # change value to string rather than DisplayString
                    ### temp printing
                    for varBind in varBinds:
                        print(' = '.join([x.prettyPrint() for x in varBind]))
                    ### temp print end
                    if return_value == "successful":
                        complete = True
                    else:
                        time.sleep(1)
                        secs += 1
            if complete:
                # clear the copy table
                if (self.snmp_set(ipaddr, ObjectType(ObjectIdentity(
                        'CISCO-CONFIG-COPY-MIB', 'ccCopyEntryRowStatus', randnum).addAsn1MibSource(
                    'file:///usr/share/snmp',
                    'http://mibs.snmplabs.com/asn1/@mib@'), 6), rw=kwargs.get('rw'))):
                    print("Job complete")

    #1.3.6.1.2.1.1.3

    # Name: snmp_get_uptime
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    #
    # Return:
    #  interfaceDescription (a string of the interface description)
    # Summary:
    #   grabs the interface id of a supplied interface.
    #   currently using 1.3.6.1.2.1.31.1.1.1.1, OiD could be updated to 1.3.6.1.2.1.2.2.1.2 for full name checking
    #     (ie GigabitEthernet X/X)
    def snmp_get_uptime(self, ipaddr,**kwargs):
        intId = 0  # intitalize as 0 as not found
        uptime = None #preassignment to avoid any errors if not found
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.1.3')),ro=kwargs.get('ro'))
        #'1.3.6.1.2.1.2.2.1.2')))

        for varBind in varBinds:
            ticks = int(varBind._ObjectType__args[1])
            seconds = ticks / 100
            uptime = datetime.timedelta(seconds=seconds)

        return uptime



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
    def snmp_get_interface_id(self, ipaddr, interface,**kwargs):
        intId = 0  # intitalize as 0 as not found
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.31.1.1.1.1')),ro=kwargs.get('ro'))
        #'1.3.6.1.2.1.2.2.1.2')))

        for varBind in varBinds:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            oidId = oidTuple[len(oidTuple) - 1]
            if (varBind._ObjectType__args[1]._value.decode("utf-8").endswith(interface)) or (varBind._ObjectType__args[1]._value.decode("utf-8") == interface):
                intId = oidId
                break;
        return intId

        # Name: snmp_get_vendor_string
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  a string saying HP, Cisco or Unknown (Change this to an int to use a switch?)
        # Summary:
        #   grabs the vendor string and checks if HP or Cisco is in it, could parse for switch model?

    def snmp_get_vendor_string(self, ipaddr,**kwargs):
        oidstring = '1.3.6.1.2.1.1.1.0'
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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

    def snmp_get_hostname(self, ipaddr,**kwargs):
        # oidstring = '1.3.6.1.4.1.9.2.1.3.0'
        oidstring = '1.3.6.1.2.1.1.5.0'
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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

    def snmp_get_crc_errors_by_id(self, ipaddr, intId, **kwargs):
        oidstring = '1.3.6.1.4.1.9.2.2.1.1.12.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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

    def snmp_get_input_errors_by_id(self, ipaddr, intId, **kwargs):
        oidstring = '1.3.6.1.2.1.2.2.1.14.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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

    def snmp_get_output_errors_by_id(self, ipaddr, intId, **kwargs):
        oidstring = '1.3.6.1.2.1.2.2.1.20.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_get_interface_id_bulk(self, ipaddr, vendor, **kwargs):
        intId = 0  # intitalize as 0 as not found
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.31.1.1.1.1')), ro=kwargs.get('ro'))
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
                elif (re.match(r"^([a-zA-Z]\d+)$", portname)): # catch for 4000 series switches
                    # switchnum = self.regex_parser_var0(r"^([A-Z])\d+$", portname)
                    switchnum = self.regex_parser_varx(r"^([A-Z])(?:(\d))?", portname)
                    if (len(switchnum) == 2):
                        returnList.append({'Switch': 1, 'Module': switchnum[0], 'Port': switchnum[1],
                                           'PortName': portname, 'Id': oidId})
            elif vendor == "Ancient Dell":
                if (re.match(r"^g(\d+)$", portname)):
                    interface = self.regex_parser_var0(r"^g(\d+)$", portname)
                    returnList.append({'Switch': 1, 'Module': 0, 'Port': int(interface),
                                       'PortName': portname, 'Id': oidId})


                # switchnum = self.regex_parser_varx(r"^\w{2}([1-9])((/\d))?/(\d+)", portname, 3)
                # if(re.match(r"^\w{2}[1-9](/\d)?/\d+", portname )):

        return returnList

    # Name: snmp_get_mac_int_bulk
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #  MacList (a list of the interfaces that mac addresses are on that are  on the switch)
    # Summary:
    #   Returns the ports that mac addresses are on, according to their ID (on vlan 1...)
    def snmp_get_mac_int_bulk(self, ipaddr, **kwargs):
        MacList = []
        #1.3.6.1.2.1.17.4.3.1.2  will give the port the ID is on X.X.X.X.X.X = Port (Integer)
        #1.3.6.1.2.1.17.4.3.1.1 will give the mac address as payload, the string IDs as 6 oid string X.X.X.X.X.X = MAC (HEX STRING E8 6A .....)
        oidstring = '1.3.6.1.2.1.17.4.3.1.2'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))

        for varBind in varBinds:
            interfaceVlan = varBind._ObjectType__args[1]._value

            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = '.'.join(map(str, oidTuple[11:]))
            MacList.append({'Id': intId, 'Port':interfaceVlan})
        return MacList


    # Name: snmp_get_mac_id_bulk
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #  MacList (a list of the macs that are  on the switch)
    # Summary:
    #   grabs all mac addresses in the table assignments, on vlan 1...
    #       for macs on other vlans need to specify by appending @vlan_id to the snmp RO
    def snmp_get_mac_id_bulk(self, ipaddr, **kwargs):
        MacList = []
        #1.3.6.1.2.1.17.4.3.1.2  will give the port the ID is on X.X.X.X.X.X = Port (Integer)
        #1.3.6.1.2.1.17.4.3.1.1 will give the mac address as payload, the string IDs as 6 oid string X.X.X.X.X.X = MAC (HEX STRING E8 6A .....)
        oidstring = '1.3.6.1.2.1.17.4.3.1.1'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))

        for varBind in varBinds:
            interfaceVlan = varBind._ObjectType__args[1]._value

            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = '.'.join(map(str, oidTuple[11:]))
            MacList.append({'Id': intId, 'Mac': self.normalize_mac(interfaceVlan.hex())})
        return MacList


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

    def snmp_get_switch_id_bulk(self, ipaddr, vendor, **kwargs):
        intId = 0  # intitalize as 0 as not found
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.47.1.1.1.1.7')),ro=kwargs.get('ro'))
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
            ### Obsolete code for finding switch letter in 4000 series, moved to modules
            # for varBind in varBinds:
            #     varName = varBind._ObjectType__args[1]._value.decode("utf-8")
            #     oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            #     oidId = oidTuple[len(oidTuple) - 1]
            #
            #     if (re.match(r"^Slot [A-Z]$", varName)):
            #         switchnum = self.regex_parser_var0(r"^Slot ([A-Z])?", varName)
            #         if switchnum is not None:
            #             returnList.append({'Switch': switchnum, 'Id': oidId})
            if len(returnList) == 0:
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

    def snmp_get_serial_number(self, ipaddr, intId, **kwargs):
        oidstring = '1.3.6.1.2.1.47.1.1.1.1.11.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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

    def snmp_get_serial_number_bulk(self, ipaddr, **kwargs):
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.47.1.1.1.1.11')),ro=kwargs.get('ro'))
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

    def snmp_get_model(self, ipaddr, intId, **kwargs):
        oidstring = '1.3.6.1.2.1.47.1.1.1.1.13.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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

    def snmp_get_software(self, ipaddr, intId,**kwargs):
        oidstring = '1.3.6.1.2.1.47.1.1.1.1.10.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_get_full_interface(self, ipaddr, intId,**kwargs):
        oidstring = '1.3.6.1.2.1.2.2.1.2.{}'.format(intId)
        # find the current vlan assignment for the port
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_get_interface_vlan(self, ipaddr, intId, vendor,**kwargs):

        if vendor == "HP":
            currentVlan = None
            for port in self.snmp_get_interface_vlan_bulk(ipaddr,vendor,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    if port["Id"] == intId:
                        currentVlan = port['Vlan']
                        break

        else:
            oidstring = '1.3.6.1.4.1.9.9.68.1.2.2.1.2.{}'.format(intId)
            # find the current vlan assignment for the port
            varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_get_interface_vlan_bulk(self, ipaddr,vendor,**kwargs):
        interfaceVlanList = []
        if vendor == "Cisco":
            oidstring = '1.3.6.1.4.1.9.9.68.1.2.2.1.2'
            varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))

            for varBind in varBinds:
                interfaceVlan = varBind._ObjectType__args[1]._value
                oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
                intId = oidTuple[len(oidTuple) - 1]
                interfaceVlanList.append({'Id':intId,'Vlan':interfaceVlan})
        elif vendor == "HP" or vendor == "Dell" or vendor == "Ancient Dell":

            oidstring = '1.3.6.1.2.1.17.7.1.4.3.1.4'
            varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))

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
    def snmp_get_interface_description(self, ipaddr, intId,**kwargs):
        oidstring = '1.3.6.1.2.1.31.1.1.1.18.{}'.format(intId)
        varBind = self.snmp_get(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_set_interface_description(self, ipaddr, intId, desc, **kwargs):
        oidstring = '1.3.6.1.2.1.31.1.1.1.18.{}'.format(intId)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), OctetString(desc)), rw=kwargs.get('rw'))
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
    def snmp_set_interface_vlan(self, ipaddr, intId, newvlan, oldvlan, vendor, **kwargs):
        if vendor == "Cisco:":
            oidstring = '1.3.6.1.4.1.9.9.68.1.2.2.1.2.{}'.format(intId)
            self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(newvlan)), rw=kwargs.get('rw'))
        # else:
        #     # oidstring = "1.3.6.1.2.1.17.7.1.4.5.1.1.{}".format(intId)
        #     # self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(newvlan)))
        #
        #     oidstring = '1.3.6.1.2.1.17.7.1.4.3.1.4'  #doesn't work
        #     varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)))
        #
        #     oldvlanbefore = None
        #     newvlanbefore = None
        #
        #     for varBind in varBinds:
        #         interfaceVlan = varBind._ObjectType__args[1]._value
        #         oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
        #         vlanId = oidTuple[len(oidTuple) - 1]
        #
        #         temp = interfaceVlan[intId]
        #         print("Before vlan:{}".format(vlanId))
        #         for i in range (len(interfaceVlan)*8):
        #             base = int(i // 8)  # which byte
        #             shift = int(i % 8)  # which bit
        #             print("i={} : {}".format(i,((interfaceVlan[base] & (128 >> shift)) >> 7 - shift) ))
        #
        #         if vlanId == newvlan:
        #             test = int.from_bytes(interfaceVlan,sys.byteorder) #sys.byteorder
        #             testp5 = test + intId
        #             # test = int(interfaceVlan,16) + intId
        #             test2 = int.to_bytes(testp5,len(interfaceVlan),byteorder=sys.byteorder)
        #
        #             # test = bin(int(interfaceVlan) + intId)
        #             print("added After vlan:{}".format(vlanId))
        #             for i in range(len(test2) * 8):
        #                 base = int(i // 8)  # which byte
        #                 shift = int(i % 8)  # which bit
        #                 print("i={} : {}".format(i, ((test2[base] & (128 >> shift)) >> 7 - shift)))
        #         elif vlanId == oldvlan:
        #             test = bin(int(interfaceVlan) - intId)
        #             print("removed After vlan:{}".format(vlanId))
        #             for i in range(len(test) * 8):
        #                 base = int(i // 8)  # which byte
        #                 shift = int(i % 8)  # which bit
        #                 print("i={} : {}".format(i, ((interfaceVlan[base] & (128 >> shift)) >> 7 - shift)))
        #
        #
        #         if vlanId == oldvlan:
        #             oldvlanbefore = [self.access_bit(interfaceVlan,i) for i in range(len(interfaceVlan)*8)]
        #         elif vlanId == newvlan:
        #             newvlanbefore = [self.access_bit(interfaceVlan,i) for i in range(len(interfaceVlan)*8)]
        #
        #
        #         # 0000 0000
        #
        #     for idx, val in enumerate(oldvlanbefore):
        #         if val ==1:
        #             print("test")#interfaceVlanList.append({'Id': idx+1, 'Vlan': vlanId})

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
    def snmp_reset_interface(self,ipaddr,intId,**kwargs):
        oidstring = '1.3.6.1.2.1.2.2.1.7.{}'.format(intId)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(2)), rw=kwargs.get('rw'))
        time.sleep(2)
        self.snmp_set(ipaddr, ObjectType(ObjectIdentity(oidstring), rfc1902.Integer(1)), rw=kwargs.get('rw'))

    # Name: snmp_get_vlan_database
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #   vlanList (list of vlans from switch)
    # Summary:
    #   Grabs list of vlans from 1.3.6.1.4.1.9.9.46.1.3.1.1.4.1 for cisco
    #   currently ignores vlan 1002 - 1005 as they are defaults on cisco
    def snmp_get_vlan_database(self, ipaddr, vendor,**kwargs):

        if vendor =="HP" or vendor =='Dell':
            oidstring = '1.3.6.1.2.1.17.7.1.4.3.1.1'
        else: #vendor == "Cisco":
            oidstring = '1.3.6.1.4.1.9.9.46.1.3.1.1.4.{}'.format('1')


        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
        vlansToIgnore = [1002, 1003, 1004, 1005]  # declare what vlans we will ignore.
        vlanList = []  # intitalize a blank list


        for varBind in varBinds:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            vlanId = oidTuple[len(oidTuple) - 1]
            if (vlanId not in vlansToIgnore):
                try:
                    vlanList.append({'ID': vlanId, "Name": varBind._ObjectType__args[1]._value.decode("utf-8")})
                except Exception as err:  # UnicodeDecodeError on hex values when presenting a mac address
                    self.verbose_printer("{} Error decoding vlan {} name:{}".format(ipaddr, vlanId, err))

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
    def snmp_get_port_poe_alloc_bulk(self, ipaddr,**kwargs):

        oidstring = '1.3.6.1.4.1.9.9.402.1.2.1.7'
        # oidstring = '1.3.6.1.4.1.9.9.402.1.2.1.7.1'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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

    def snmp_get_port_activity_bulk(self, ipaddr,**kwargs):

        oidstring = '1.3.6.1.2.1.2.2.1.8'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_get_interface_description_bulk(self, ipaddr,**kwargs):
        # oidstring = '1.3.6.1.2.1.31.1.1.1.1'
        oidstring = '1.3.6.1.2.1.31.1.1.1.18'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_get_interface_trunking_bulk(self, ipaddr, vendor,**kwargs):
        interfaceTrunkingList = []
        if vendor == "Cisco":
            oidstring = '1.3.6.1.4.1.9.9.46.1.6.1.1.14'
            varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))


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
        #   vendor (string)
        #      -The vendor type: Cisco,HP,Dell
        # Return:
        #  cdp neighbour list
        # Summary:
        #   grabs the cdp or LLDP infothat is connected to each interface. Currently not grabbing field 10 of lldp
    def snmp_get_neighbour_bulk(self, ipaddr, vendor, **kwargs):
        interfaceCdpList = []

        if vendor == "Cisco" or vendor == "HP":
            oidString = '1.3.6.1.4.1.9.9.23.1.2.1.1'
            typeList = [4,6,7,8]
            categoryIndex = 13
        elif vendor =="Dell":
            oidString = '1.0.8802.1.1.2.1.4.1.1'
            typeList = [7,9] # add 10 to get some type info?
            categoryIndex = 10
        else:
            return interfaceCdpList
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidString)),ro=kwargs.get('ro'))

        # add separate call to get IP, since Cisco doesn't like to give it with everything else
        if vendor == "Cisco":
            varBinds = varBinds + self.snmp_walk(ipaddr, ObjectType(ObjectIdentity("{}.4".format(oidString))),ro=kwargs.get('ro'))


        for varBind in varBinds:
            # Category labels (6 = Name, 7 = Remote Port, 8 = Type of device)
            oidCategory = varBind._ObjectType__args[0]._ObjectIdentity__oid._value[categoryIndex]
            if vendor == "Cisco" or vendor == "HP":
                if oidCategory == 6:
                    cdpCategory = "Name"
                elif oidCategory == 7:
                    cdpCategory = "RemotePort"
                elif oidCategory == 8:
                    cdpCategory = "Type"
                elif oidCategory == 4:
                    cdpCategory = "IP"

            elif vendor =="Dell":
                if oidCategory == 9:
                    cdpCategory = "Name"
                elif oidCategory ==7 :
                    cdpCategory = "RemotePort"
                # elif oidCategory == 8:
                #     cdpCategory = "Type"
                # elif oidCategory == 9:
                #     cdpCategory = "IP"

            if oidCategory  in typeList:  # only care about oids of 6,7 or 8
                try:
                    if cdpCategory == "IP":
                        cdpValue = socket.inet_ntoa(varBind._ObjectType__args[1]._value)
                    elif cdpCategory == 'Name' and vendor == 'HP':
                        cdpValue = str(varBind._ObjectType__args[1]._value)
                    else:
                        cdpValue = varBind._ObjectType__args[1]._value.decode("utf-8")
                    oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
                    intId = oidTuple[len(oidTuple) - 2]

                    interfaceCdpList.append({'Category': cdpCategory, 'Id': intId, 'Value': cdpValue})
                except Exception as err: #UnicodeDecodeError on hex values when presenting a mac address
                    self.verbose_printer("{} Error assigning Neighbour Value:{}".format(ipaddr,err))


        return interfaceCdpList

        # Name: snmp_get_voice_vlan_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  voice vlan list
        # Summary:
        #   grabs the voice vlan that is connected to each interface
    def snmp_get_voice_vlan_bulk(self, ipaddr,**kwargs):
        oidstring = '1.3.6.1.4.1.9.9.68.1.5.1.1.1'
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
        interfaceVlanList = []

        for varBind in varBinds:
            interfaceVlan = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceVlanList.append({'Id': intId, 'Vlan': interfaceVlan})

        return interfaceVlanList

    # Name: snmp_get_port_security_violations_bulk
    # Input:
    #   ipaddr (string)
    #      -The ipaddress/hostname to grab info from
    # Return:
    #  port security violations list
    # Summary:
    #   grabs the a list of port security violations on ports
    def snmp_get_port_security_violations_bulk(self, ipaddr, **kwargs):
        oidstring = '1.3.6.1.4.1.9.9.315.1.2.1.1.9 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
        interfaceViolationsList = []

        for varBind in varBinds:
            interfaceViolations = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceViolationsList.append({'Id': intId, 'Violations': interfaceViolations})

        return interfaceViolationsList

        # Name: snmp_get_input_errors_bulk
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  input errors list
        # Summary:
        #   grabs the a list of input errors
    def snmp_get_input_errors_bulk(self, ipaddr,**kwargs):
        oidstring = '1.3.6.1.2.1.2.2.1.14 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_get_output_errors_bulk(self, ipaddr,**kwargs):
        oidstring = '1.3.6.1.2.1.2.2.1.20 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
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
    def snmp_get_input_counters_bulk(self, ipaddr,**kwargs):
        oidstring = '1.3.6.1.2.1.2.2.1.10 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
        interfaceCounterList = []

        for varBind in varBinds:
            interfaceCounters = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceCounterList.append({'Id': intId, 'Counters': interfaceCounters})

        oidstring = '1.3.6.1.2.1.2.2.1.11 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))

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
    def snmp_get_output_counters_bulk(self, ipaddr,**kwargs):
        oidstring = '1.3.6.1.2.1.2.2.1.16 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
        interfaceCounterList = []

        for varBind in varBinds:
            interfaceCounters = varBind._ObjectType__args[1]._value
            # if '/' in interfaceDescription:
            oidTuple = varBind._ObjectType__args[0]._ObjectIdentity__oid._value
            intId = oidTuple[len(oidTuple) - 1]
            interfaceCounterList.append({'Id': intId, 'Counters': interfaceCounters})

        oidstring = '1.3.6.1.2.1.2.2.1.17 '
        varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))

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
    def snmp_get_mac_table_bulk(self, ipaddr, vendor,**kwargs):

        oidstring = '1.3.6.1.2.1.17.4.3.1'
        macList=[]

        if vendor == "HP":
            varBinds = self.snmp_walk(ipaddr, ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
            i = 0
            while (i < len(varBinds) / 3):
                macList.append({"MAC": varBinds[i]._ObjectType__args[1]._value,
                                "InterfaceID": varBinds[i + int(len(varBinds) / 3)]._ObjectType__args[1]._value,
                                "Status": varBinds[i + int((len(varBinds) / 3) * 2)]._ObjectType__args[1]._value,
                                "Vlan": "N/A"})
                i += 1

        elif vendor == "Cisco":

            vlanList = self.snmp_get_vlan_database(ipaddr,vendor,ro=kwargs.get('ro'))

            for vlan in vlanList:
                #Return should always be a factor of 3. X=MAC, X+1=Port, X+2=status
                varBinds = self.vlan_at_snmp_walk(ipaddr,vlan['ID'],ObjectType(ObjectIdentity(oidstring)),ro=kwargs.get('ro'))
                i = 0
                while ( i < len(varBinds)/3):
                    macList.append({"MAC": varBinds[i]._ObjectType__args[1]._value,
                                    "InterfaceID": varBinds[i + int(len(varBinds)/3)]._ObjectType__args[1]._value,
                                    "Status": varBinds[i + int((len(varBinds)/3)*2)]._ObjectType__args[1]._value,
                                    "Vlan": vlan['ID']})
                    i += 1
        elif vendor == 'Dell':
            self.verbose_printer("{} Not printing Dell switches. Need to enable them manually with enable-dot1d-mibwalk")


        return macList

        # Name: snmp_get_switch_data_full
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to grab info from
        # Return:
        #  a data structure (a list of strings of the interface descriptions)
        # Summary:
        #   grabs information from the switch to put in a datastructure

    def snmp_get_switch_data_full(self, ipaddr,**kwargs):
        # test = self.snmp_get_switch_id_bulk(ipaddr)

        vendor = self.snmp_get_vendor_string(ipaddr,ro=kwargs.get('ro'))
        switchStruct = StackStruct(ipaddr, vendor)
        switchStruct.vlanList  = self.snmp_get_vlan_database(ipaddr,vendor,ro=kwargs.get('ro'))
        if vendor != "None Found":
            switchStruct.hostname = self.snmp_get_hostname(ipaddr,ro=kwargs.get('ro'))

            switchStruct.uptime = self.snmp_get_uptime(ipaddr,ro=kwargs.get('ro'))

            for switch in self.snmp_get_switch_id_bulk(ipaddr,vendor,ro=kwargs.get('ro')):
                if (switchStruct.getSwitch(switch['Switch']) is None):
                    switchStruct.addSwitch(switch['Switch'])
                switchStruct.getSwitch(switch['Switch']).id = switch['Id']

            for switch in switchStruct.switches: #individual calls for this seem to be resolving faster than a bulk
                switch.serialnumber=self.snmp_get_serial_number(ipaddr,switch.id,ro=kwargs.get('ro'))
                switch.model = self.snmp_get_model(ipaddr,switch.id,ro=kwargs.get('ro'))
                switch.version = self.snmp_get_software(ipaddr,switch.id,ro=kwargs.get('ro'))



            #get interfaces and create them on the structure if they are not there
            for port in self.snmp_get_interface_id_bulk(ipaddr,vendor,ro=kwargs.get('ro')):
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
            for port in self.snmp_get_port_poe_alloc_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None and switchStruct.getSwitch(port['Switch']) is not None and switchStruct.getSwitch(port['Switch']).id is not None: #added catch for provisioned switch 1 being missing
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
                    pass #CURRENTLY DES NOTHING!
                    #port['Power'] = "N/A" #TODO update this to align with not found verbage Currently does nothing
                #hard set using module 0^


            #go through interface returns (includes vlans, so need to map id to port)
            #get port status (2 is up, 1 is down)
            for port in self.snmp_get_port_activity_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None: #ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.status = port['Status']
            #get trunk mode
            for port in self.snmp_get_interface_trunking_bulk(ipaddr,vendor,ro=kwargs.get('ro')):
                if port is not None: #ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.portmode = port['TrunkMode']
            #Get descriptions
            for port in self.snmp_get_interface_description_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.description = port['Description']
            # Get Vlans on ports
            for port in self.snmp_get_interface_vlan_bulk(ipaddr,vendor,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.datavlan = port['Vlan']
                        foundport.datavlanname = next((vlanEntry['Name'] for vlanEntry in switchStruct.vlanList if vlanEntry["ID"] ==  port['Vlan']), None)
                        # foundport.datavlanname = [vlanEntry['Name'] for vlanEntry in switchStruct.vlanList if
                        #                 'ID' in vlanEntry and vlanEntry["ID"] == port['Vlan']]

           # Get CDP information for ports
            for port in self.snmp_get_neighbour_bulk(ipaddr,vendor,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        if port['Category'] == "Name": # 6 for Cisco, 9 for Dell
                            foundport.cdpname = port['Value']
                        elif port['Category'] == "RemotePort":
                            foundport.cdpport = port['Value']
                        elif port['Category'] == "Type": #for Dell, could include 10 as a type?
                            foundport.cdptype = port['Value']
                        elif port['Category'] == "IP": #
                            foundport.cdpip = port['Value']

            for port in self.snmp_get_port_security_violations_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.psviolations = port['Violations']


            # Get input Errors for ports
            for port in self.snmp_get_input_errors_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.inputerrors = port['Errors']
                        foundport.historicalinputerrors.append((int(datetime.datetime.now().strftime("%Y%m%d%H%M")),port['Errors']))

            # Get output Errors for ports
            for port in self.snmp_get_output_errors_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.outputerrors = port['Errors']
                        foundport.historicaloutputerrors.append((int(datetime.datetime.now().strftime("%Y%m%d%H%M")),port['Errors']))

            # Get input Counters for ports
            for port in self.snmp_get_input_counters_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.inputcounters = port['Counters']
                        foundport.historicalinputcounters.append((int(datetime.datetime.now().strftime("%Y%m%d%H%M")),port['Counters']))

            for port in self.snmp_get_output_counters_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.outputcounters = port['Counters']
                        foundport.historicaloutputcounters.append((int(datetime.datetime.now().strftime("%Y%m%d%H%M")), port['Counters']))

            for port in self.snmp_get_voice_vlan_bulk(ipaddr,ro=kwargs.get('ro')):
                if port is not None:  # ignore vlan interfaces and non existent interfaces
                    foundport = switchStruct.getPortById(port['Id'])
                    if foundport is not None:
                        foundport.voicevlan = port['Vlan']

        if len(switchStruct.switches) == 0:
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
            print('------- CONNECTING to switch {} -------'.format(ipaddr))

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

        self.handle_banners(vendor, net_connect)

        return net_connect

        # Name: create_connection_custom
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to connect to
        #   vendor (string)
        #      -The device type:
        #   username (string)
        #      -The username to use to login to the switch
        #   password (string)
        #      -The password to use to login to the switch
        #   enable (string)
        #      -The enable password to login to the switch
        #   port (string)
        #      -The port number to use to login to the switch ie 22
        # Return:
        #   net_connect (connection handler)
        # Summary:
        #   Sets up a connection to the provided ip address. Currently setup to connect to cisco switches
    def create_connection_custom(self, ipaddr, vendor, username, password, enable, port):
        if 'verbose' in self.cmdargs and self.cmdargs.verbose:
            print('------- CONNECTING to switch {}-------'.format(ipaddr))

        # Switch Parameters
        net_sw = {
            'device_type': vendor,
            'ip': ipaddr,
            'username': username,
            'password': password,
            'secret': enable,
            'port': port,
            'verbose': False,
            # 'username_pattern':"sername:"
            # 'session_log':'SSHLOG.txt',
        }
        # net_sw["username_pattern"] = "sername:"
        # SSH/Telnet Connection
        net_connect = netmiko.ConnectHandler(**net_sw)
        self.handle_banners(vendor, net_connect)

        return net_connect

        # Name: create_connection_manual
        # Input:
        #   ipaddr (string)
        #      -The ipaddress/hostname to connect to
        #   vendor (string)
        #      -The device type:
        #   username (string)
        #      -The username to use to login to the switch
        #   password (string)
        #      -The password to use to login to the switch
        #   enable (string)
        #      -The enable password to login to the switch
        #   port (string)
        #      -The port number to use to login to the switch ie 22
        # Return:
        #   net_connect (connection handler)
        # Summary:
        #   Sets up a connection to the provided ip address. manually does all login process and then
        #       dispatches back to netmiko. Used for ssh v1 switches with weird login promptsprompts
    def create_connection_manual(self, ipaddr, vendor, username, password, enable, port, un_prompt,pw_prompt):
        if 'verbose' in self.cmdargs and self.cmdargs.verbose:
            print('------- CONNECTING to switch {}-------'.format(ipaddr))

        # Switch Parameters
        ConnectionClass = netmiko.terminal_server.TerminalServerTelnet
        net_sw = {
            'device_type': 'terminal_server_telnet',
            'ip': ipaddr,
            'username': username,
            'password': password,
            'secret': enable,
            'port': port,
            'verbose': False,
            # 'username_pattern':"sername:"
            # 'session_log':'SSHLOG.txt',
        }
        net_connect = ConnectionClass(**net_sw)

        # output = net_connect.read_channel()
        time.sleep(2)
        # Manually handle the Username and Password
        # max_loops = 10
        # i = 1
        # while i <= max_loops:
        for _ in range(10):
            output = net_connect.read_channel()

            if un_prompt in output:
                net_connect.write_channel(username + '\r\n')
                time.sleep(1)
                output = net_connect.read_channel()

            # Search for password pattern / send password
            if pw_prompt in output:
                net_connect.write_channel(password + '\r\n')
                time.sleep(.5)
                output = net_connect.read_channel()
                # Did we successfully login
                if '>' in output or '#' in output:
                    break

            net_connect.write_channel('\r\n')
            time.sleep(.5)
        # We are now logged into the end device
        # Dynamically reset the class back to the proper Netmiko class
        netmiko.redispatch(net_connect, device_type=vendor)

        self.handle_banners(vendor,net_connect)

        if 'verbose' in self.cmdargs and self.cmdargs.verbose:
            print('------- Successfully connected to switch {}-------'.format(ipaddr))

        return net_connect

        # Name: create_connection_manual
        # Input:
        #   net_connect (netmiko connection)
        #      -The netmiko connection
        #   vendor (string)
        #      -The device type:
        # Return:
        #   net_connect (connection handler)
        # Summary:
        #   Sets up a connection to the provided ip address. manually does all login process and then
        #       dispatches back to netmiko. Used for ssh v1 switches with weird login promptsprompts
    def handle_banners(self, vendor, net_connect):
        if "procurve" in vendor:
            net_connect.send_command("\n")
        return

        # Name: vendor_enable
        # Input:
        #   vendor: (string)
        #       -The vendor or device type of the connection
        #   net_connect (connection handler)
        #      -The active connection to enable
        # Return:
        #   success (boolean if successful)
        # Summary:
        #   enable mode regardless of vendor
        #   TODO Add error handling

    def vendor_enable(self,vendor,net_connect):
        if vendor in ["Cisco", "cisco_ios", "cisco_ios"]:
            net_connect.enable()
        elif vendor in ["HP", "hp_procurve", "hp_procurve_telnet"]:
            self.hp_connection_enable(net_connect)

        return net_connect.check_enable_mode()

        # Name: hp_connection_enable
        # Input:
        #   net_connect (connection handler)
        #      -The active connection to enable
        # Return:
        #   success (boolean if successful)
        # Summary:
        #   enable mode for HP switches that ask for Username/password for enable
    def hp_connection_enable(self, net_connect):

        # result = net_connect.send_command("enable", expect_string="Username:")
        # result = net_connect.send_command(self.config.username, expect_string="Password:")
        # result = net_connect.send_command(self.config.password)
        try:
            result = net_connect.send_command_timing("enable")
            result = net_connect.send_command_timing(self.config.username)
            result = net_connect.send_command_timing(self.config.password)
        except Exception as err:
            print(err)

        return net_connect.check_enable_mode()

       # Name: vendor_enable
        # Input:
        #   vendor: (string)
        #       -The vendor or device type of the connection
        #   net_connect (connection handler)
        #      -The active connection to enable
        # Return:
        #   success (boolean if successful)
        # Summary:
        #   enable mode regardless of vendor
        #   TODO Add error handling

    def vendor_enable_manual(self,vendor,net_connect,username,password,enable):
        if vendor in ["Cisco", "cisco_ios"]:
            try:
                result = net_connect.send_command_timing("enable")
                result = net_connect.send_command_timing(enable)
            except Exception as err:
                print(err)
        elif vendor in ["HP", "hp_procurve"]:
            self.hp_connection_enable_manual(net_connect,username,password)

        return net_connect.check_enable_mode()

        # Name: hp_connection_enable_manual
        # Input:
        #   net_connect (connection handler)
        #      -The active connection to enable
        #   username (string)
        #       username to use
        #   password (string)
        #       password to use
        # Return:
        #   success (boolean if successful)
        # Summary:
        #   enable mode for HP switches that ask for Username/password for enable
    def hp_connection_enable_manual(self, net_connect,username,password):

        # result = net_connect.send_command("enable", expect_string="Username:")
        # result = net_connect.send_command(self.config.username, expect_string="Password:")
        # result = net_connect.send_command(self.config.password)
        try:
            result = net_connect.send_command_timing("enable")
            result = net_connect.send_command_timing(username)
            result = net_connect.send_command_timing(password)
        except Exception as err:
            print(err)

        return net_connect.check_enable_mode()

    # Name: print_config_results
    # Input:
    #   ipaddr: (string)
    #       -The IP of the switch
    #   result: (string)
    #      -The net_connect result string
    #   command: (string)
    #      -The command applied
    # Return:
    #   success (boolean if no error)
    # Summary:
    #   simplify printing the results of applying a configuration set
    #   TODO Add error handling
    def print_config_results(self,ipaddr,result,command):
        if any(word in result.lower() for word in ["invalid input"]):
            print("###{}### ERROR APPLYING: {} ".format(ipaddr, command))
            return False
        else:
            print("###{}### APPLIED: {} ".format(ipaddr, command))
            return True


    ####################
    ##GENERAL COMMANDS##
    ####################

    # Name: normalize_mac
    # Input:
    #   address
    #      -This variable will be modified to follow mac format
    # Summary:
    #  normalize mac will modify provided mac address to the following standard AAAA.BBBB.CCCC.DDDD
    def normalize_mac(self, address):
        tmp3 = address.rstrip().lower().translate({ord(":"): "", ord("-"): "", ord(" "): "", ord("."): ""})
        if len(tmp3) % 4 == 0:
            return '.'.join(a + b + c + d for a, b, c, d in
                            zip(tmp3[::4], tmp3[1::4], tmp3[2::4], tmp3[3::4]))  # insert a period every four chars
        else:
            if len(tmp3) < 4:
                return tmp3
            else:
                print("Please enter a mac address in a group of 4")
                sys.exit()


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

        # Name: custom_printer (will deprecate verbose_printer)
        # Input:
        #   printType
        #      -This variable holds the type of print function, verbose or debug for example
        #   *printvar
        #      -This variable(s) will allow the function to be passed two vars, 1 for what to print if verbose,
        #      and 1 to print if not.
        # Summary:
        #   custom printer currently is passed a print type variable (printType) and 1-2 strings to print
        #   the 1st string is what to print if verbose, the second is what to print if not.
        #   printvar accepts a variable number of values in case nothing will be printed for not printType
        #   custom printer will return True if printType is active, and false if not (redundant?)

    def custom_printer(self,printType, *printVar):
        # if in mode of type printtype, print the first printvar variable and return that it is in verbose mode
        if printType in self.cmdargs and eval("self.cmdargs.{}".format(printType)):
            print(printVar[0])
            return True
        # if in specified mode, print the first printvar variable
        else:
            if len(printVar) > 1:
                print(printVar[1])
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
        findval = re.findall(regex, input, re.MULTILINE)
        if len(findval) > 0:
            return findval[0]
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
        findval = re.findall(regex, input, re.MULTILINE)
        if len(findval) > 0 :
            return findval[0]
            # if len(findval[0]) > numMatches:

        else:
            return None



    # Name: email_zip_file
    # Input:
    #   msg_to
    #      -String containing address to send message to
    #   msg_body
    #      -String containing the message body
    #   zipfilename
    #      -String containing the filename of the zipped file to send (currently sending from activitycheck/processedfiles/
    # Summary:
    #  email a zipped summary file
    def email_zip_file(self,msg_subject,msg_to,msg_body,zipfilename):
        try:
            self.verbose_printer("##### Emailing now #####")

            zf = open(os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.zip".format(zipfilename)), 'rb')

            # Create the message
            themsg = MIMEMultipart()
            themsg["From"] = "admin@localhost"
            themsg["Subject"] = msg_subject
            themsg["To"] = msg_to
            # themsg["Body"]="Processing completed in {} seconds\n{} switches SUCCESSFULLY processed\n{} switches FAILED during processing\n ".format(
            #      int((time.time() - total_start) * 100) / 100, len(self.successful_switches),len(self.failure_switches) )

            themsg.preamble = 'I am not using a MIME-aware mail reader.\n'
            msg = MIMEBase('application', 'zip')
            msg.set_payload(zf.read())
            encoders.encode_base64(msg)
            msg.add_header('Content-Disposition', 'attachment',
                           filename=zipfilename + '.zip')


            themsg.attach(msg)

            #create the body of the email


            themsg.attach(MIMEText(msg_body, 'plain'))

            themsg = themsg.as_string()

            # send the message
            smtp = smtplib.SMTP()
            smtp.connect()
            smtp.sendmail("admin@localhost", msg_to.split(","), themsg)
            smtp.close()

        except smtplib.SMTPException:
            print("Failed to send Email")
        except Exception as err:
            print(err)

        # Name: email_with_attachment
        # Input:
        #   msg_to
        #      -String containing address to send message to
        #   msg_body
        #      -String containing the message body
        #   zipfilename
        #      -String containing the filename of the zipped file to send (currently sending from activitycheck/processedfiles/
        # Summary:
        #  email a zipped summary file
    def email_with_attachment(self, msg_subject, msg_to, msg_body, filename):
        try:
            self.verbose_printer("##### Emailing now #####")
            image_data = open(filename,'rb').read()

            # Create the message
            themsg = MIMEMultipart()
            themsg["From"] = "admin@localhost"
            themsg["Subject"] = msg_subject
            themsg["To"] = msg_to
            # themsg["Body"]="Processing completed in {} seconds\n{} switches SUCCESSFULLY processed\n{} switches FAILED during processing\n ".format(
            #      int((time.time() - total_start) * 100) / 100, len(self.successful_switches),len(self.failure_switches) )

            themsg.preamble = 'I am not using a MIME-aware mail reader.\n'
            ctype, encoding = mimetypes.guess_type(filename)
            if ctype is None or encoding is not None:
                ctype = "application/octet-stream"

            maintype, subtype = ctype.split("/", 1)

            if maintype == "text":
                fp = open(filename)
                # Note: we should handle calculating the charset
                attachment = MIMEText(fp.read(), _subtype=subtype)
                fp.close()
            elif maintype == "image":
                fp = open(filename, "rb")
                attachment = MIMEImage(fp.read(), _subtype=subtype)
                fp.close()
            elif maintype == "audio":
                fp = open(filename, "rb")
                attachment = MIMEAudio(fp.read(), _subtype=subtype)
                fp.close()
            else:
                fp = open(filename, "rb")
                attachment = MIMEBase(maintype, subtype)
                attachment.set_payload(fp.read())
                fp.close()
                encoders.encode_base64(attachment)
            attachment.add_header("Content-Disposition", "attachment", filename=filename)
            themsg.attach(attachment)
            # image = MIMEImage(image_data,name=os.path.basename(filename))
            # themsg.attach(image)

            # create the body of the email

            themsg.attach(MIMEText(msg_body, 'plain'))

            themsg = themsg.as_string()

            # send the message
            smtp = smtplib.SMTP()
            smtp.connect()
            smtp.sendmail("admin@localhost", msg_to.split(","), themsg)
            smtp.close()

        except smtplib.SMTPException:
            print("Failed to send Email")
        except Exception as err:
            print(err)

    ############################
    ###SwitchStruct COMMANDS####
    ############################
    # Name: Create_Readable_Activity_File
    # Input:
    #   status_filename (raw string)
    #      -This variable will contains the regex expression to use.
    #   iplist (list of strings)
    #      -This variable contains the string to apply the regex search to.
    # Return:
    #   Nothing (change to boolean for success)
    # Summary:
    #   Create readable activity file will create a csv file out of the ips in the provided
    def create_readable_activity_file(self,status_filename,**kwargs):
        try:
            successful_files = []
            failure_files = []
            if 'file' in kwargs and kwargs['file'] is not None or kwargs['maincommand'] == "status_checks": #have default of all IPS with statusChecks
                if 'file' in kwargs and kwargs['file'] is not None:
                    file = open(os.path.join(kwargs['file']), "r")
                else:
                    file = open(os.path.abspath(os.path.join(os.sep, 'usr', 'lib', 'capt', "activitycheckIPlist")), "r")
                self.custom_printer("verbose","##### ip file opened:{} #####".format(file))
                iplist = []
                for ip in file:
                    #processing for custom RO strings
                    ip = ip.split(',')
                    ip = ip[0] #ensure only the IP will be used
                    #end processing
                    iplist.append(ip.rstrip())
                file.close()

        except FileNotFoundError:
            print("##### ERROR iplist files not found #####")
        except Exception as err:
            print("##### ERROR with processing:{} #####".format(err))

        TotalStatus = StackStruct.getHeader(self.cmdargs)

        # By default grabs all existing statcheck files, this could be changed to only act on the iplist provided

        if 'file' in self.cmdargs and self.cmdargs.file is not None and kwargs['maincommand'] =='database_commands' or kwargs[
            'maincommand'] == "status_checks" and 'limit' in self.cmdargs and self.cmdargs.limit:
            self.custom_printer("verbose","##### Creating Limited Summary List #####")
            fileList = [f + "-statcheck.bz2" for f in iplist]
        else:
            self.custom_printer("verbose","##### Creating Full Summary List #####")
            fileList = [f for f in os.listdir(os.path.join(self.log_path, "activitycheck", "rawfiles", "active"))
                        if f.endswith('-statcheck.bz2')]
        for ip in fileList:
            # process
            try:
                # LOADING Compressed files
                self.custom_printer("debug", "## DBG - Opening pickled file from active for {} ##".format(ip))
                with bz2.open(os.path.join(self.log_path, "activitycheck", "rawfiles", "active", ip), "rb") as f:
                    self.custom_printer("debug", "## DBG - loading pickled file from active for {} ##".format(ip))
                    SwitchStatus = pickle.load(f, encoding='utf-8')

                    SL_keywords = {'executive_mode': ('xecutive' in self.cmdargs and self.cmdargs.xecutive is True)}
                    if 'fmnet' in kwargs and kwargs['fmnet'] is not None:
                        SL_keywords['remove_empty_filter'] = kwargs['fmnet']
                    elif 'ignorefield' in kwargs and kwargs['ignorefield']:
                        SL_keywords['remove_empty_filter'] = kwargs['ignorefield']

                    TotalStatus += SwitchStatus.appendSingleLineCustom(**SL_keywords)

                    self.custom_printer("debug", "## DBG - Appending {} to successful files ##".format(ip))
                    successful_files.append("{}-statcheck.bz2".format(ip))
            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                print("FILE ERROR {}-statcheck:{}".format(ip, err.args[0]))
                self.custom_printer("debug", "## DBG - Error in create readable activity file ##")
                failure_files.append("{}-statcheck.bz2".format(ip))

        zf = zipfile.ZipFile(
            os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.zip".format(status_filename)),
            mode='w',
            compression=zipfile.ZIP_DEFLATED,
        )
        try:
            zf.writestr(status_filename, TotalStatus)
        finally:
            zf.close()
        return successful_files,failure_files
