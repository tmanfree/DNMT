#!/usr/bin/env python3

#TODO Add Try/Except loops for proper error handling
#TODO flash verification skipping for 4500 & 2950T models
#Warning - Does not work on 4500 or 2950 T models

import re
import sys
import subprocess,platform,os,time,datetime
import difflib
import pickle,bz2
import zipfile #imports for summary filescompression imports
import collections



#3rd party imports
import netmiko
from pathos.multiprocessing import ProcessingPool as Pool


#local subroutine import
from DNMT.procedure.subroutines import SubRoutines
from DNMT.procedure.switchstruct import StackStruct


class DBcmds:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
                                           datetime.date.today().strftime('%Y%m%d'))

    def find_description(self):
        matchlist = []
        print("##### Beginning to search for \"{}\" #####".format(self.cmdargs.searchstring))
        fileList = [f for f in os.listdir(os.path.join(self.subs.log_path,"activitycheck", "rawfiles","legacy")) if f.endswith('-statcheck.bz2')]
        # for ip in fileList:
        for ipindex, ip in enumerate(fileList):

            # process
            try:
                self.subs.verbose_printer("##### Now Checking {} for matches file {} / {} #####".format(ip,ipindex+1,len(fileList)))
                # LOADING Compressed files
                # portList = []
                with bz2.open(os.path.join(self.subs.log_path, "activitycheck", "rawfiles", "legacy", ip), "rb") as f:
                    SwitchStatus = pickle.load(f, encoding='utf-8')
                    if 'name' in self.cmdargs and (self.cmdargs.name is None or self.cmdargs.name.lower() in SwitchStatus.hostname.lower()): #insensitive hostname checking
                        portList = []
                        if ('sensitive' in self.cmdargs and not self.cmdargs.sensitive) and (
                                'exact' in self.cmdargs and not self.cmdargs.exact):  #case insensitive partial
                            portList = SwitchStatus.getPortByDesc_Partial_Insensitive(self.cmdargs.searchstring)
                        elif ('sensitive' in self.cmdargs and not self.cmdargs.sensitive) and (
                                'exact' in self.cmdargs and self.cmdargs.exact):  # case insensitive exact
                            portList = SwitchStatus.getPortByDesc_Exact_Insensitive(self.cmdargs.searchstring)
                        elif ('sensitive' in self.cmdargs and self.cmdargs.sensitive) and ('exact' in self.cmdargs and self.cmdargs.exact):  # exact case matching
                            portList = SwitchStatus.getPortByDesc_Exact(self.cmdargs.searchstring)
                        elif ('sensitive' in self.cmdargs and self.cmdargs.sensitive) and (
                                'exact' in self.cmdargs and not self.cmdargs.exact):  #case matching not exact
                            portList = SwitchStatus.getPortByDesc_Partial(self.cmdargs.searchstring)

                        if len(portList) > 0:
                            self.subs.verbose_printer("##### {} Matches found in {} #####".format(len(portList),ip))
                        for port in portList:
                            matchlist.append({'Ip':SwitchStatus.ip,'Hostname':SwitchStatus.hostname,'Port':port.portname, 'Desc':port.description,})

            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                print("FILE ERROR {}:{}".format(ip, err.args[0]))
        print("{} Matches found\n".format(len(matchlist)))
        if 'file' in self.cmdargs and self.cmdargs.file is None:
            if 'csv' in self.cmdargs and self.cmdargs.csv:
                print ("Switch IP, Hostname, Port, Description")
                for port in matchlist:
                    print("{},{},{}".format(port['Ip'],port['Hostname'],port['Port'],port['Desc']))
            else:
                for port in matchlist:
                    print("Switch:{}\nHostname:{}\nPort:{}\nDescription:{}\n".format(port['Ip'],port['Hostname'],port['Port'],port['Desc']))
        else:
            try:
                with open(self.cmdargs.file, 'w') as f:
                    print("Now writing to file {}".format(self.cmdargs.file))
                    if 'csv' in self.cmdargs and self.cmdargs.csv:
                        self.subs.verbose_printer("Writing to file as CSV ")
                        for port in matchlist:
                            f.write("{},{},{},{}".format(port['Ip'],port['Hostname'], port['Port'], port['Desc']))
                    else:
                        self.subs.verbose_printer("Writing to file as raw text")
                        for port in matchlist:
                            f.write("Switch:{}\nHostname:{}\nPort:{}\nDescription:{}\n".format(port['Ip'],port['Hostname'], port['Port'], port['Desc']))
                    f.close()
                    self.subs.verbose_printer("Writing Complete to CSV")
            except Exception as err:
                print("ERROR ### Something went wrong writing to file")


    # def find_mac_address(self):
    #     totalstart = time.process_time()
    #     if 'ipfile' in self.cmdargs and self.cmdargs.ipfile is not None:
    #         ipList = open(os.path.join(self.cmdargs.ipfile), "r")
    #     else:
    #         ipList = open(os.path.abspath(os.path.join(os.sep, 'usr', 'lib', 'capt', "activitycheckIPlist")), "r")
    #     for ip in ipList:
    #
    #         ipaddr = ip.rstrip()
    #         if 'name' in self.cmdargs and self.cmdargs.name is not None:
    #             hostname = self.subs.snmp_get_hostname(ipaddr)
    #             if self.cmdargs.name.lower() in hostname.lower():
    #                 self.Find_Mac_Table(ipaddr)
    #
    #         else:
    #             self.Find_Mac_Table(ipaddr)


        print("Total Time to search for Macs:{} seconds".format(time.process_time() - totalstart))

    def find_mac_address_in_db(self):
        try:
            self.subs.custom_printer("debug", "## DBG - Opening mac db file ##")

            with bz2.open(os.path.join(self.subs.log_path, "maccheck", "rawfiles", "macs.db"),
                          "rb") as historical_mac_file:
                self.subs.custom_printer("debug", "## DBG - Loading historical mac data ##")
                historical_mac_data = pickle.load(historical_mac_file)
                historical_mac_file.close()
                match_entry_list = [f for f in historical_mac_data if
                                    self.subs.normalize_mac(self.cmdargs.searchstring) in self.subs.normalize_mac(
                                        f["MAC"].hex())]
                if len(match_entry_list) > 0:
                    if 'csv' in self.cmdargs and not self.cmdargs.csv:
                        print("\n### {} matches to \"{}\" found ###".format( len(match_entry_list), self.subs.normalize_mac(self.cmdargs.searchstring)))

                        for match in match_entry_list:
                            print(
                                "MAC:{}\nSwitch:{}\nInterface:{}\nMacs on interface:{}\nlast update:{}\n\n".format(
                                    self.subs.normalize_mac(match["MAC"].hex()),
                                    match['switchIP'], match["InterfaceID"], match["MACCount"], match['timestamp']))
                    else:
                        print("MAC,Switch IP,Interface,#of Macs on interface,last update")

                        for match in match_entry_list:
                            print("{},{},{},{},{}".format(
                                self.subs.normalize_mac(match["MAC"].hex()),
                                match['switchIP'],
                                match["InterfaceID"], match["MACCount"], match['timestamp']))
                else:
                    self.subs.verbose_printer(" {} matches to \"{}\" found".format(len(match_entry_list), self.subs.normalize_mac(self.cmdargs.searchstring)))

        except FileNotFoundError as err:
            print("##### {} -  No previous mac data found")



    # def Find_Mac_Table(self,ipaddr): #TODO merge functionality with MACSearch general
    #     try:
    #         match_entry_list = []
    #         start = time.process_time()
    #         if self.subs.ping_check(ipaddr):
    #             vendor = self.subs.snmp_get_vendor_string(ipaddr)
    #
    #             if vendor == "HP": #currently only search on HP switches
    #                 self.subs.verbose_printer("{} searching for MAC:{}".format(ipaddr, self.subs.normalize_mac(self.cmdargs.searchstring)))
    #                 list = self.subs.snmp_get_mac_table_bulk(ipaddr, vendor)
    #                 self.subs.verbose_printer("{} Time to grab Macs:{} seconds".format(ipaddr, time.process_time() - start))
    #
    #                 match_entry_list = [f for f in list if self.subs.normalize_mac(self.cmdargs.searchstring) in self.subs.normalize_mac(f["MAC"].hex())]
    #                 if len(match_entry_list) > 0:
    #                     print("\n### {} - {} matches to \"{}\" found ###".format(ipaddr, len(match_entry_list), self.subs.normalize_mac(self.cmdargs.searchstring)))
    #                     for match in match_entry_list:
    #                         print("MAC:{} Interface:{} Vlan:{}".format(self.subs.normalize_mac(match["MAC"].hex()),
    #                                                                    match["InterfaceID"], match["Vlan"]))
    #                 else:
    #                     self.subs.verbose_printer("{} - {} matches to \"{}\" found".format(ipaddr, len(match_entry_list), self.subs.normalize_mac(self.cmdargs.searchstring)))
    #     except Exception as err:
    #         print(err)




    def create_port_security_report(self): # similar to create readable activity file in statuschecks, combine both?
        try:
            status_filename = "{}-FullStatus.csv".format(datetime.datetime.now().strftime('%Y-%m-%d-%H%M'))
            successful_files,failure_files = self.subs.create_readable_activity_file(status_filename,**vars(self.cmdargs))

            if 'email' in self.cmdargs and self.cmdargs.email is not None:
                msg_subject = "FMNet Weekly Port-Security Report - {}".format(datetime.date.today().strftime('%Y-%m-%d'))
                body = "{} switches SUCCESSFULLY added to the summary file\n".format(len(successful_files))
                body += "{} switches FAILED to add to the summary file\n".format(len(failure_files))
                body += "\n--------------------------------------------------------------------------------------\n\n"


                if len(successful_files) > 0:
                    body += "--- List of files SUCCESSFULLY added to summary file ---\n"
                    for entry in successful_files:
                        body += "{}\n".format(entry)
                if len(failure_files) > 0:
                    body += "--- List of files FAILED to be added to summary file ---\n"
                    for entry in failure_files:
                        body += "{}\n".format(entry)
                self.subs.email_zip_file(msg_subject,self.cmdargs.email,body,status_filename)
        except Exception as err:
            print(err)
