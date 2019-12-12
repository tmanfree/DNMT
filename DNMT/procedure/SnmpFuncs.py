#!/usr/bin/env python3

from netmiko import ConnectHandler
import random
import re
import socket
import time
from pysnmp.hlapi import *


##########TEST
# from pysnmp.entity.rfc3413.oneliner import cmdgen
# from pysnmp.proto import rfc1902


#from procedure import subroutines
### absolute pathing
#from DNMT.procedure import subroutines
from DNMT.procedure.subroutines import SubRoutines
import sys

class SnmpFuncs:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)

    def Change_Port_Vlan(self):
        vlanList = self.subs.snmp_vlan_grab(self.cmdargs.ipaddr)


        for vlan in vlanList:
            print("Vlan ID:{} Vlan Name:{}".format(vlan["ID"],vlan["Name"].decode("utf-8")))



        # Find the ID of the requested interface
        intId = self.subs.snmp_get_interface_id(self.cmdargs.ipaddr, self.cmdargs.interface)

        fullInterface = self.subs.snmp_get_full_interface(self.cmdargs.ipaddr, intId)
        intDescription = self.subs.snmp_get_interface_description(self.cmdargs.ipaddr, intId)
        currentVlan = self.subs.snmp_get_interface_vlan(self.cmdargs.ipaddr, intId)

        #enter vlan id to change to
        bLoop = True  # TODO make this more efficient
        while (bLoop):
            print("Interface {} Description:{}".format(fullInterface,intDescription))
            vlanResponse = input("Current Vlan is {} Enter VLAN ID to change to:".format(currentVlan ))
            if any(d['ID'] == int(vlanResponse) for d in vlanList):
                bLoop = False
            else:
                print("Please enter an existing Vlan ID")


        response = input("Do you want to change vlan on port {} from {} to {}?\n"
                         "enter (yes) to proceed:".format(self.cmdargs.interface,currentVlan,vlanResponse))
        if not response == 'yes':
            self.subs.verbose_printer('Did not proceed with change.')
            sys.exit(1)

        #set new vlan
        self.subs.snmp_set_interface_vlan(self.cmdargs.ipaddr, intId, vlanResponse)

        #check what vlan is now
        newVlan = self.subs.snmp_get_interface_vlan(self.cmdargs.ipaddr, intId)

        if int(newVlan) == int(vlanResponse): #
            print("Vlan updated to Vlan {}".format(newVlan))
        else:
            print("vlan not updated, Vlan is still {}".format(newVlan))

