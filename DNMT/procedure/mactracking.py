#!/usr/bin/env python3

import re
import sys
import subprocess,platform,os,time,datetime
import getpass
import difflib
import smtplib
import tempfile
from email import encoders
from email.message import EmailMessage
import pickle,bz2 #imports for statchecks

import zipfile #imports for summary filescompression imports






#3rd party imports
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from collections import defaultdict
import netmiko
from pathos.multiprocessing import ProcessingPool as Pool

#local subroutine import
from DNMT.procedure.subroutines import SubRoutines
from DNMT.procedure.switchstruct import StackStruct



class MacTracking:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        # self.log_path = os.path.abspath(os.path.join(os.sep, 'var', 'log', 'dnmt'))
        # self.subs.log_path = os.path.abspath(os.path.join(os.sep, 'var', 'log', 'dnmt'))
        self.successful_switches = [] #used for activity tracking
        self.failure_switches = [] #used for activity tracking
        self.successful_files = []#used for activity tracking
        self.failure_files = []  # used for activity tracking

    def mac_tracking_begin(self):
        iplist = []
        historical_mac_data = [] # will hold the mac data list of dicts {mac,
        total_start = time.time()
        if not os.path.exists(os.path.join(self.subs.log_path, "maccheck", "rawfiles")):
            self.subs.custom_printer("debug","## DBG - Creating maccheck/rawfiles directory ##")
            os.makedirs(os.path.join(self.subs.log_path, "maccheck", "rawfiles"))
        # if not os.path.exists(os.path.join(self.subs.log_path, "maccheck", "processedfiles")):
        #     self.subs.custom_printer("debug", "## DBG - Creating maccheck/processedfiles directory ##")
        #     os.makedirs(os.path.join(self.subs.log_path, "maccheck", "processedfiles"))
        # Specifying a file only changes what IPs are updated, right now the status check grabs all existing files in
        # the raw data folder
        try:
            self.subs.custom_printer("debug", "## DBG - Opening statcheck file from legacy ##")

            with bz2.open(os.path.join(self.subs.log_path, "maccheck", "rawfiles", "macs.db"), "rb") as historical_mac_file:
                self.subs.custom_printer("debug", "## DBG - Loading historical mac data ##")
                historical_mac_data = pickle.load(historical_mac_file)
                historical_mac_file.close()
        except FileNotFoundError as err:
            print("##### {} -  No previous mac data found, one will be created if searching #####")

        try:
            if 'file' in self.cmdargs and self.cmdargs.file is not None:
                file = open(os.path.join(self.cmdargs.file), "r")
            else:
                file = open(os.path.abspath(os.path.join(os.sep, 'usr', 'lib', 'capt', "activitycheckIPlist")), "r")
            self.subs.verbose_printer("##### file opened:{} #####".format(file))

            for ip in file:
                iplist.append(ip.rstrip())
            file.close()

            # pool = Pool(len(iplist))  # 4 concurrent processes
            # results = pool.map(self.single_search, iplist)

            #TODO CHANGE to do them with individual processes
            for ip in iplist:

                # self.subs.config.ro = self.config.ro #reset to default to ensure previous ones did not bork things
                custom_ro_check = ip.split(',')
                ro_string = self.subs.config.ro
                if len(custom_ro_check) > 1:
                    ro_string = custom_ro_check[1]
                    ip = custom_ro_check[0]

                try:
                    result = self.mac_tracking(ip,ro_string)
                    if result[0]:
                        self.successful_switches.append(result[1])
                        #update macdb list with found macs
                        for new_mac_entry in result[2]:
                            try:
                                historical_mac_entry = next(entry for entry in historical_mac_data if entry['MAC'] == new_mac_entry['MAC'])
                                # if found_mac_entry[''] #if found_mac_entry_timestamp is bigger or the count is smaller, update list # if not 1, go for the largest mac count? this would catch the highest up the chain
                                if new_mac_entry['MACCount'] <= historical_mac_entry['MACCount']:
                                    historical_mac_entry['MACCount'] = new_mac_entry['MACCount']
                                    historical_mac_entry['timestamp'] = int(datetime.datetime.now().strftime('%Y%m%d%H%M'))
                                    historical_mac_entry['switchIP'] = ip
                                    historical_mac_entry['InterfaceID'] = new_mac_entry["InterfaceID"]
                            except StopIteration:
                                self.subs.verbose_printer("##### MAC {} not found adding to list #####".format(new_mac_entry['MAC']))
                                historical_mac_data.append({'MAC': new_mac_entry['MAC'], "switchIP": ip,
                                                            "InterfaceID":new_mac_entry["InterfaceID"],
                                                            "MACCount": new_mac_entry["MACCount"], "timestamp": int(
                                        datetime.datetime.now().strftime('%Y%m%d%H%M'))})

                            except Exception as err:
                                print("ERROR PROCESSING MAC ADDRESS RETURN {}:{}".format(ip, err))


                    else:
                        self.failure_switches.append(result[1])
                except Exception as err:
                    print("ERROR PROCESSING FILE {}:{}".format(ip, err))
            self.subs.verbose_printer("##### Total Processing Complete, Total Time:{} seconds #####".format( int((time.time() - total_start) * 100) / 100))
        except FileNotFoundError:
            print("##### ERROR iplist files not found #####")
        except Exception as err:
            print ("##### ERROR with processing:{} #####".format(err))


        # write out active status for combining into statcheck csv
        self.subs.custom_printer("debug", "## DBG - Opening Active file to save NewSwitchStatus to ##")
        with bz2.BZ2File(
                os.path.join(self.subs.log_path, "maccheck", "rawfiles","macs.db"),
                'wb') as sfile:
            self.subs.custom_printer("debug", "## DBG - Writing NewSwitchStatus to active statcheck ##")
            pickle.dump(historical_mac_data, sfile)
            sfile.close()

        # # After all processes return, read in each pickle and create a single output file?
        # status_filename = "{}-FullStatus.csv".format(datetime.datetime.now().strftime('%Y-%m-%d-%H%M'))
        # try:
        #     # self.Create_Readable_Activity_File(status_filename,iplist)
        #     self.successful_files,self.failure_files = self.subs.create_readable_activity_file(status_filename,**vars(self.cmdargs))
        # except Exception as err:
        #     print("##### ERROR creating Summary File: {} #####".format(err))
        #
        # #Compress
        # # with open(os.path.join(self.log_path, "activitycheck", "processedfiles", status_filename), 'rb') as f_in:
        # #     with gzip.open(os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.gz".format(status_filename)), 'wb') as f_out:
        # #         shutil.copyfileobj(f_in, f_out)
        # #EMail finished file:
        # try:
        #     ##################
        #     if 'email' in self.cmdargs and self.cmdargs.email is not None:
        #         msg_subject = "updated activitycheck - {}".format(datetime.date.today().strftime('%Y-%m-%d'))
        #
        #         body = "Processing completed in {} seconds\n".format(int((time.time() - total_start) * 100) / 100)
        #         body += "{} switch state files SUCCESSFULLY updated\n".format(len(self.successful_switches))
        #         body += "{} switch state files FAILED to update\n".format(len(self.failure_switches))
        #         body += "{} switch states SUCCESSFULLY added to the summary file\n".format(len(self.successful_files))
        #         body += "{} switch states FAILED to add to the summary file\n".format(len(self.failure_files))
        #         body += "\n--------------------------------------------------------------------------------------\n\n"
        #
        #         if len(self.successful_switches) > 0:
        #             body += "--- List of switch statuses SUCCESSFULLY updated ---\n"
        #             for entry in self.successful_switches:
        #                 body += "{}\n".format(entry)
        #         if len(self.failure_switches) > 0:
        #             body += "--- List of switch statuses that FAILED to update ---\n"
        #             for entry in self.failure_switches:
        #                 body += "{}\n".format(entry)
        #         if len(self.successful_files) > 0:
        #             body += "--- List of files SUCCESSFULLY added to summary file ---\n"
        #             for entry in self.successful_files:
        #                 body += "{}\n".format(entry)
        #         if len(self.failure_files) > 0:
        #             body += "--- List of files FAILED to be added to summary file ---\n"
        #             for entry in self.failure_files:
        #                 body += "{}\n".format(entry)
        #         # self.subs.email_zip_file(msg_subject,self.cmdargs.email,body,status_filename)
        #         self.subs.email_zip_file(msg_subject, self.cmdargs.email, body, status_filename)
        #     #######################
        # except Exception as err:
        #     print(err)

    def mac_tracking(self, ipaddr,ro_string):
        try:
            start = time.time()
            self.subs.verbose_printer("##### {} -  Processing #####".format(ipaddr))
            self.subs.custom_printer("debug", "## DBG - Grabbing switch data through SNMP ##")

            try:
                vendor = self.subs.snmp_get_vendor_string(ipaddr, ro=ro_string)
                mac_list = self.subs.snmp_get_mac_table_bulk(ipaddr, vendor, ro=ro_string)
                # interface_list = {} #used for counting number of macs on a port
                if len(mac_list) > 0:
                    interface_list = defaultdict(list)
                    #process to find out how many on each port
                    for entry in mac_list:
                        interface_list[entry["InterfaceID"]].append(entry["MAC"])
                    for entry in mac_list:
                        entry["MACCount"] = len(interface_list[entry['InterfaceID']])

                    return True,ipaddr,mac_list
                else:
                    return False,ipaddr,mac_list
            except Exception as err: #currently a catch all to stop linux from having a conniption when reloading
                print("##### {} UNKNOWN ERROR:{} #####".format(ipaddr,err.args[0]))
                return False,ipaddr,None

        #
        #     NewSwitchStatus  = self.subs.snmp_get_switch_macs(ipaddr,ro=ro_string)
        #
        #
        # #TODO Check if a previous static check exists, and load it if it does, otherwise create it and write it out
        #     try:
        #         if len(NewSwitchStatus.switches) == 0:
        #             raise ValueError('##### {} ERROR - No Data in switchstruct #####'.format(ipaddr))
        #
        #         #load archival information (may have removed switches in it)
        #         self.subs.custom_printer("debug", "## DBG - Opening statcheck file from legacy ##")
        #         with bz2.open(os.path.join(self.subs.log_path, "activitycheck", "rawfiles","legacy","{}-statcheck.bz2".format(ipaddr)), "rb") as myNewFile:
        #             self.subs.custom_printer("debug", "## DBG - Loading legacy into OldSwitchStatus ##")
        #             OldSwitchStatus = pickle.load(myNewFile)
        #
        #         # if len(OldSwitchStatus.switches) != len(NewSwitchStatus.switches):
        #         #TODO Check if the existing file is empty or if there is a different number of switches. If empty,save NewSwitcStatus instead
        #         #If different number, check which switch is which based on serial numbers to try to save historical data?
        #         #Then write out OldSwitchStatus to a archive file/folder and write the new one out
        #         #TODO Why not use the newswitch status instead? Data may be lost if a switch is down when the new one is there? could fix that by adding any missing data to the new one?
        #
        #         #update the new switch status with archival info
        #         self.subs.custom_printer("debug", "## DBG - Updating switch status with OldSwitchStatus ##")
        #         for tempswitch in NewSwitchStatus.switches:
        #             #if the switchnumber doesn't exist in the archive status file, add it
        #             if OldSwitchStatus.getSwitch(tempswitch.switchnumber) is None:
        #                 OldSwitchStatus.addExistingSwitch(tempswitch) #will be a link, but should be fine
        #                 # OldSwitchStatus.addExistingSwitch(copy.deepcopy(tempswitch))
        #                 # OldSwitchStatus.addExistingSwitch(tempswitch.__dict__.copy())
        #             else:
        #                 for tempmodule in tempswitch.modules:
        #                     for newport in tempmodule.ports:
        #                         oldport = OldSwitchStatus.getPortByPortName(newport.portname)
        #                         if oldport is not None: #check if the port exists in archival data
        #                             if newport.activityChanged(oldport): #if the port info has changed...
        #                                 self.Port_Updating_Active(newport, oldport) #update the new port
        #                                 self.Port_Updating_Archive(oldport, newport)  # update any old ports that exist
        #                             else: #otherwise, grab the historical data to paste in here
        #                                 newport.lastupdate = oldport.lastupdate
        #                                 newport.deltalastin = oldport.deltalastin
        #                                 newport.deltalastout = oldport.deltalastout
        #                                 newport.historicalinputerrors = oldport.historicalinputerrors
        #                                 newport.historicaloutputerrors = oldport.historicaloutputerrors
        #                                 newport.historicalinputcounters = oldport.historicalinputcounters
        #                                 newport.historicaloutputcounters = oldport.historicaloutputcounters
        #                         else: #if it is a new port entry
        #                             newport.lastupdate = datetime.date.today().strftime('%Y-%m-%d')
        #                             newport.deltalastin = 0
        #                             newport.deltalastout = 0
        #
        #
        #
        #         #update the old status file for archive. This should prevent losing data if there is an outage during collection
        #         # for tempswitch in OldSwitchStatus.switches: #remove this stuff, and just update the old with new values after assigning to the new
        #         #     for tempmodule in tempswitch.modules:
        #         #         for oldport in tempmodule.ports:
        #         #             newport = NewSwitchStatus.getPortByPortName(oldport.portname) #Changed 20200601 from id Cisco changing IDs....
        #         #             if newport is not None: #if the port exists in the new status check to see if it has changed
        #         #                 if oldport.activityChanged(newport): #if the port has changed, update it, otherwise leave it
        #         #                     self.Port_Updating_Archive(oldport, newport) #update any old ports that exist for the archive
        #
        #
        #
        #         #TODO Compare the two files now
        #         #write out active status for combining into statcheck csv
        #         self.subs.custom_printer("debug", "## DBG - Opening Active file to save NewSwitchStatus to ##")
        #         with bz2.BZ2File(
        #                 os.path.join(self.subs.log_path, "activitycheck", "rawfiles","active", "{}-statcheck.bz2".format(ipaddr)),
        #                 'wb') as sfile:
        #             self.subs.custom_printer("debug", "## DBG - Writing NewSwitchStatus to active statcheck ##")
        #             pickle.dump(NewSwitchStatus, sfile)
        #             sfile.close()
        #
        #         #Write out archival switchstatus to load again later
        #         self.subs.custom_printer("debug", "## DBG - Opening legacy file to save OldSwitchStatus to ##")
        #         with bz2.BZ2File(
        #                 os.path.join(self.subs.log_path, "activitycheck", "rawfiles","legacy", "{}-statcheck.bz2".format(ipaddr)),
        #                 'wb') as sfile:
        #             self.subs.custom_printer("debug", "## DBG - Writing OldSwitchStatus to legacy statcheck ##")
        #             pickle.dump(OldSwitchStatus, sfile)
        #             sfile.close()
        #
        #         # self.successful_switches.append(ipaddr)
        #         returnval = (True, ipaddr)
        #     except FileNotFoundError:
        #         print("##### {} -  No previous status file found, one will be created #####".format(ipaddr))
        #         OldSwitchStatus = NewSwitchStatus
        #
        #         for tempswitch in OldSwitchStatus.switches:
        #             for tempmodule in tempswitch.modules:
        #                 for tempport in tempmodule.ports:
        #                     tempport.lastupdate = datetime.date.today().strftime('%Y-%m-%d')
        #                     tempport.deltalastin = 0
        #                     tempport.deltalastout = 0
        #         # self.successful_switches.append(ipaddr)
        #         returnval = (True, ipaddr)
        #         with bz2.BZ2File(
        #                 os.path.join(self.subs.log_path, "activitycheck", "rawfiles","active", "{}-statcheck.bz2".format(ipaddr)),
        #                 'wb') as sfile:
        #             pickle.dump(OldSwitchStatus, sfile)
        #             sfile.close()
        #
        #         with bz2.BZ2File(
        #                 os.path.join(self.subs.log_path, "activitycheck", "rawfiles","legacy", "{}-statcheck.bz2".format(ipaddr)),
        #                 'wb') as sfile:
        #             pickle.dump(OldSwitchStatus, sfile)
        #             sfile.close()
        #
        #
        #
        #     except ValueError as err:
        #         print(err)
        #         # self.failure_switches.append(ipaddr)
        #         returnval = (False,ipaddr)
        #     except Exception as err: #currently a catch all to stop linux from having a conniption when reloading
        #         print("##### {} FILE ERROR:{} #####".format(ipaddr,err.args[0]))
        #         self.subs.custom_printer("debug", "## DBG - Error in Activity_Tracking ##")
        #         # self.failure_switches.append(ipaddr)
        #         returnval = (False, ipaddr)
        #
        #     end = time.time()
        #     self.subs.verbose_printer("##### {} -  Processing Complete, time:{} seconds #####".format(ipaddr, int((end - start) * 100) / 100))
        #
        #     return returnval
        except Exception as err: #catch all exception
            print("##### {} UNKNOWN ERROR:{} #####".format(ipaddr, err.args[0]))
            # self.failure_switches.append(ipaddr)
            end = time.time()
            self.subs.verbose_printer(
                "##### {} -  Processing aborted/failure, time:{} seconds #####".format(ipaddr, int((end - start) * 100) / 100))
            return (False,ipaddr)

