#All encompassing file,
import re
import sys
import subprocess,platform,os,time,datetime
import difflib
import pickle
import collections



#3rd party imports
import netmiko
from pathos.multiprocessing import ProcessingPool as Pool

#local subroutine import
from DNMT.procedure.subroutines import SubRoutines



class Functions:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        #TODO Check cmdargs to find out where to put the log files
        self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
                                           datetime.date.today().strftime('%Y%m%d'))

    def Change_Port_Vlan(self):
        vlanList = self.subs.snmp_get_vlan_database(self.cmdargs.ipaddr)


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

        response = input("Do you want to change description on port {} from {}?\n"
                         "enter (yes) to proceed:".format(self.cmdargs.interface, intDescription))
        if not response == 'yes':
            self.subs.verbose_printer('No new Description.')
            sys.exit(1)
        response = input("Enter new description:")
        self.subs.snmp_set_interface_description(self.cmdargs.ipaddr,intId,response)
        newDescription = self.subs.snmp_get_interface_description(self.cmdargs.ipaddr, intId)

        if newDescription == response: #
            print("Description updated to \"{}\"".format(response))
        else:
            print("Description not updated, still \"{}\"".format(newDescription))

