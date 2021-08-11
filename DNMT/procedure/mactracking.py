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
from filelock import Timeout, FileLock

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
        file_path = os.path.join(self.subs.log_path, "maccheck", "rawfiles", "macs.db")
        lock = FileLock("{}.lock".format(file_path))
        try:
            self.subs.custom_printer("debug", "## DBG - Opening statcheck file from legacy ##")
            lock.acquire(timeout=10)

            with bz2.open(os.path.join(self.subs.log_path, "maccheck", "rawfiles", "macs.db"), "rb") as historical_mac_file:
                self.subs.custom_printer("debug", "## DBG - Loading historical mac data ##")
                historical_mac_data = pickle.load(historical_mac_file)
                historical_mac_file.close()
                self.subs.custom_printer("debug", "## DBG - Completed loading Mac database {} ##".format(file_path))
        except FileNotFoundError as err:
            print("##### {} -  No previous mac data found, one will be created if searching #####".format(file_path))
        except Timeout as err:
            print("##### {} -  Lock file exists #####".format(file_path))
        finally:
            lock.release()

        if 'file' in self.cmdargs and self.cmdargs.file is not None:
            file_path = os.path.join(self.cmdargs.file)
        else:
            file_path = os.path.abspath(os.path.join(os.sep, 'usr', 'lib', 'capt', "activitycheckIPlist"))
        # added file locking
        lock = FileLock("{}.lock".format(file_path))
        try:
            self.subs.custom_printer("debug", "## DBG - Opening iplist {} ##".format(file_path))
            lock.acquire(timeout=10)
            file = open(file_path, "r")

            self.subs.custom_printer("debug", "## DBG - Completed opening iplist {} ##".format(file_path))

            for ip in file:
                iplist.append(ip.rstrip())
            file.close()
            self.subs.custom_printer("debug", "## DBG - Completed loading iplist {} ##".format(file_path))

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
        except Timeout as err:
            print("##### {} -  Lock file exists #####".format(file_path))
        except Exception as err:
            print ("##### ERROR with processing:{} #####".format(err))
        finally:
            lock.release()



        # write out active status for combining into statcheck csv
        file_path = os.path.join(self.subs.log_path, "maccheck", "rawfiles","macs.db")
        lock = FileLock("{}.lock".format(file_path))

        try:
            self.subs.custom_printer("debug", "## DBG - Opening {} to save mac database to ##".format(file_path))
            lock.acquire(timeout=10)
            with bz2.BZ2File(file_path,'wb') as sfile:
                self.subs.custom_printer("debug", "## DBG - Writing Mac database {} ##".format(file_path))
                pickle.dump(historical_mac_data, sfile)
                sfile.close()
                self.subs.custom_printer("debug", "## DBG - Completed Writing Mac database {} ##".format(file_path))
        except Timeout as err:
            print("##### {} -  Lock file exists #####".format(file_path))
        finally:
            lock.release()




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
        except Exception as err: #catch all exception
            print("##### {} UNKNOWN ERROR:{} #####".format(ipaddr, err.args[0]))
            # self.failure_switches.append(ipaddr)
            end = time.time()
            self.subs.verbose_printer(
                "##### {} -  Processing aborted/failure, time:{} seconds #####".format(ipaddr, int((end - start) * 100) / 100))
            return (False,ipaddr)

