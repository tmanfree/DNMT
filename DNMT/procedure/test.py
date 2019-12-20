#!/usr/bin/env python3

import re
import sys
import subprocess,platform,os,time,datetime
import getpass
import difflib
import pickle



#3rd party imports
import netmiko
from pathos.multiprocessing import ProcessingPool as Pool

#local subroutine import
from DNMT.procedure.subroutines import SubRoutines



class Test:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
                                           datetime.date.today().strftime('%Y%m%d'))


    def Power_Check(self):
        power = self.subs.snmp_get_port_poe_alloc_bulk(self.cmdargs.ipaddr)
        ports = self.subs.snmp_get_port_activity_bulk(self.cmdargs.ipaddr)

        #test removing things this has issues with uplinks like 1/1/1 = 51 resolving to switch 1 port 1
        removalList = []
        for poePort in power:
            found = False
            for activePort in ports:
                if str(activePort["Switch"]) == str(poePort["Switch"]) and str(activePort["Port"]) == str(poePort["Port"]):
                    found = True
                    break;
            if not found:
                removalList.append(poePort)
        for port in removalList:
            power.remove(port)
        print(power)

    def Switch_Check(self):
        #3560X with ten gig uplink doesn't show gi 1/1-2 only ten 1/1-2.
        start = time.time()
        test = self.subs.snmp_get_switch_data_full(self.cmdargs.ipaddr)
        end = time.time()
        print("first time:{} seconds".format(end-start))
        # test.printStack()
        # test.printSingleLine()
        if 'csv' in self.cmdargs and self.cmdargs.csv is not None:
            test.exportCSV(self.cmdargs.csv)
        else:
            test.printStack()