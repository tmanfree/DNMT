#!/usr/bin/env python3

#TODO Add Try/Except loops for proper error handling
#TODO flash verification skipping for 4500 & 2950T models
#Warning - Does not work on 4500 or 2950 T models

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



class Check:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
                                           datetime.date.today().strftime('%Y%m%d'))

    def sw_3650_precheck(self, net_connect,flashnum,before_swcheck_dict,packages):
        #designed for 3650s, 9300s
        #instead of verification should it just check for files in flash:?
        veribool = True

        packages_list = re.findall(r'''(?:^\w+\s+\w{2}\s+\w\s+\w\s+)(\w+) #packagename [x][0]
                                                     (?:\s+)(\S+) #file to check [x][1]
                                                     ''', packages, re.VERBOSE | re.MULTILINE)
        #create a list to iterate through, getting rid of repeats. This will save time from duplicate verifications
        package_test_list = []
        for item in packages_list:
            if not item[1] in package_test_list:
                package_test_list.append(item[1])
#        package_test_list.append("TEST")

        for f in package_test_list: #Added Delay factor of 4 for timing
            verification = net_connect.send_command('Verify /md5 {}{} '.format(flashnum, f), delay_factor=4)
            if "ERROR".lower() in verification.lower():
                veribool = False
            self.subs.verbose_printer("{} {}{}\n{}".format(before_swcheck_dict["ip"], flashnum, f, verification))

        self.subs.verbose_printer("{} {} verification complete".format(before_swcheck_dict["ip"], flashnum))
        return veribool

    def basic_sw_precheck(self, net_connect, flashnum, before_swcheck_dict):
        # Took a different approach than the 3650, will exit out as soon as there is a problem, ideal?

        # create a list of files to test
        package_test_list = []
        try:
            package_test_list.append(re.findall(r'^BOOT path-list\s+:\s+flash:(\S+)', before_swcheck_dict["boot"], re.MULTILINE)[0])
            package_test_list.append(re.findall(r'^Config file\s+:\s+flash:(\S+)', before_swcheck_dict["boot"], re.MULTILINE)[0])
            #TODO extract each binary/packages when multiple files are listed
            # package_test_list.append(re.findall('flash:(\S+)', before_swcheck_dict["boot"], re.DOTALL))
        except Exception as e: # super broad exception temporarily
            return False

        for f in package_test_list:
            verification = net_connect.send_command('Verify /md5 {}{} '.format(flashnum, f), max_loops=1000) #verifying, but showing % Invalid input detected at '^' marker. on 2960x for .bin
            self.subs.verbose_printer("{} {}{}\n{}".format(before_swcheck_dict["ip"], flashnum, f, verification))
            if "ERROR".lower() in verification.lower():
                self.subs.verbose_printer(
                    "***{} {} verification ERROR!\n {}**".format(before_swcheck_dict["ip"], flashnum, verification))
                return False

        self.subs.verbose_printer("***{} {} verification successfully completed***".format(before_swcheck_dict["ip"], flashnum))
        return True



    def var_compare(self, before_str, after_str, vartext, ipaddr):
        before_list = before_str.splitlines(1)
        after_list = after_str.splitlines(1)
        sumstring = "################# {} {} ####################\n".format(ipaddr,vartext)
        if before_str == after_str:
            sumstring += "{} entries are the same\n".format(vartext)
            self.subs.verbose_printer(sumstring)
            return sumstring,"{} identical".format(vartext)
        elif (len(after_list) / len(before_list)) >= 0.8:
            sumstring += "{} are similar \nOld Entries:{}\nNew Entries:{}\n".format(vartext, len(before_list),
                                                                                    len(after_list))
            self.subs.verbose_printer(sumstring)
        else:
            sumstring += "{} are significantly different\nOld Entries:{}\nNew Entries:{}\n".format(vartext,
                                                                                                   len(before_list),
                                                                                                   len(after_list))
            self.subs.verbose_printer(sumstring)

        diff = difflib.ndiff(before_list, after_list)
        delta = ''.join(x for x in diff if x.startswith('- ') or x.startswith('+ '))
        #print(delta)
        return sumstring,"{} Different Before:-,After:-\n{}".format(vartext, delta)




    def var_list_compare(self, before_list, after_list, vartext, ipaddr):
        #TODO add logic to record which items are missing?
        sumstring = "################# {} {} ####################\n".format(ipaddr,vartext)
        # if (before_list == after_list):
        if collections.Counter(before_list) == collections.Counter(after_list):
            sumstring += "{} entries are the same\n".format(vartext)
            self.subs.verbose_printer(sumstring)
            return sumstring
        else:
            NewEntries = set(after_list) - set(before_list)
            MissingEntries = set(before_list) - set(after_list)
            if len(before_list) == len(after_list):
                sumstring += "{} are the same length, but different entries\n".format(vartext)

                if len(MissingEntries) > 0:
                    sumstring += "Missing Entries: " + str(MissingEntries) + "\n"
                if len(NewEntries) > 0:
                    sumstring += "New Entries: " + str(NewEntries)+ "\n"

                self.subs.verbose_printer(sumstring)
                return sumstring

            elif (len(after_list) / len(before_list)) >= 0.8:
                sumstring += "{} are similar \nOld Entries:{}\nNew Entries:{}\n".format(vartext, len(before_list),
                                                                                        len(after_list))
                if len(MissingEntries) > 0:
                    sumstring += "Missing Entries: " + str(MissingEntries) + "\n"
                if len(NewEntries) > 0:
                    sumstring += "New Entries: " + str(NewEntries)+ "\n"
                self.subs.verbose_printer(sumstring)

            else:
                sumstring += "{} are significantly different\nOld Entries:{}\nNew Entries:{}\n".format(vartext,
                                                                                                       len(before_list),
                                                                                                       len(after_list))
                if len(MissingEntries) > 0:
                    sumstring += "Missing Entries: " + str(MissingEntries)+ "\n"
                if len(NewEntries) > 0:
                    sumstring += "New Entries: " + str(NewEntries)+ "\n"
                self.subs.verbose_printer(sumstring)

            diff = difflib.ndiff(before_list, after_list)
            delta = ''.join(x for x in diff if x.startswith('- ') or x.startswith('+ '))
            #print(delta)
            return sumstring



    # def ping_check(self,sHost):
    #     try:
    #         output = subprocess.check_output("ping -{} 1 {}".format('n' if platform.system().lower() == "windows" else 'c', sHost), shell=True)
    #     except Exception as e:
    #         return False
    #     return True

    def begin(self):
        if self.cmdargs.upgrade_check == 'single' and self.cmdargs.ipaddr:
            result = self.single_search(self.cmdargs.ipaddr)
            #not printing right now!
            if ('apply' in self.cmdargs and self.cmdargs.apply) or(
                    'compare' in self.cmdargs and self.cmdargs.compare is not None):
                print(result["Print_Sum"])

                self.subs.verbose_printer(result["summary"])
        elif self.cmdargs.upgrade_check == 'batch' and self.cmdargs.file:
            iplist = []
            file = open(self.cmdargs.file, "r")
            for ip in file:
                iplist.append(ip.rstrip())
            file.close()
            #pool = Pool(4) # 4 concurrent processes
            pool = Pool(len(iplist))  # 4 concurrent processes
            results = pool.map(self.single_search,iplist)
            #results = pool.map(self.single_search,iplist)

            #TODO add printout for comparing as well as reload
            if ('apply' in self.cmdargs and self.cmdargs.apply) or (
                    'compare' in self.cmdargs and self.cmdargs.compare is not None):
                for result in results:
                    # if "identical" in result["Version"] :
                    print(result["Print_Sum"])

                    self.subs.verbose_printer(result["summary"]) # make this printing by default?
            print("***Batch Done***")
        elif self.cmdargs.upgrade_check == 'view_log':
            self.list_logs(self.cmdargs.ipaddr)
       #add functionality to parse the various log files that are created, so you dont manually look:
        print("***Job Complete, Exiting Program***")

    def list_logs(self, ipaddr):
        # check log folder to see what files are available:
        # < IP > -Before.txt
        # < IP > - < Check | Reload > -After.txt
        # < IP > - < Check | Reload > -Diff.txt
        # < IP > - < Check | Reload > -Sum.txt
        # < IP > -Verification.txt

        # os.path.join(self.config.logpath, ipaddr + "-Before.txt")
        # test = os.listdir(os.path.join(self.config.logpath))
        availablefiles = []
        for file in os.listdir(os.curdir):
            if file.endswith(".txt"):
                if re.search('^'+ ipaddr + '-', file) is not None:
                    availablefiles.append(file)

        if len(availablefiles) > 0:
            availablefiles.append("Exit")
            selectionmade = -1

            while (selectionmade != len(availablefiles)):
                print("***The following files hae been found, please select one***")
                print("***CURRENTLY WORKS WITH BEFORE FILES***")
                for num, name in enumerate(availablefiles, start=0):
                    print("[{}]: {}".format(num, name))

                response = input("Please enter your selection:")
                try:
                    selectionmade = int(response)
                    if selectionmade >= len(availablefiles) or selectionmade < 0:
                        raise ValueError
                except ValueError:
                    print("\nInvalid Response, please enter a valid number from 0 - {}\n".format(len(availablefiles)-1))
                    selectionmade = -1

                if (selectionmade == len(availablefiles)-1): #exit is added to available selections
                    print("Exiting out")
                    sys.exit(0)
                if selectionmade >= 0: #igrnore -1 error case
                    print("Selection is {}".format(availablefiles[selectionmade]))
                    self.view_logs(availablefiles[selectionmade])
                # selectionmade = -1 #reset selection made to -1
        else:
            print("No files found in the current folder, exiting")
            sys.exit(0)
    def list_entries(self, swcheck_dict):
        print("***The following entries have been found, please select one***")
        for name in swcheck_dict.keys():
            print("{}:".format(name))
        print("\n(list,all and exit are valid)")

        return

    def view_logs(self, filename):
        if (re.search('-Before.txt', filename) is not None) or (re.search('-After.txt', filename) is not None):
            with open(filename, "rb") as file:
                before_swcheck_dict = pickle.load(file)
                file.close()
            if len(before_swcheck_dict) > 0:
                selectionmade = ""
                self.list_entries(before_swcheck_dict)
                while not (selectionmade == "exit"):
                    response = input("Please enter your selection:")
                    try:
                        selectionmade = response
                        if selectionmade not in before_swcheck_dict.keys() and selectionmade not in ["exit","list","all"] :
                            raise KeyError
                        elif (selectionmade == "exit"):
                            print("Exiting out")
                            return
                        elif (selectionmade == "list"):
                            self.list_entries(before_swcheck_dict)
                        elif (selectionmade == "all"):
                            print(before_swcheck_dict)  # TODO MAKE THIS PRETTY
                        # print("Selection is {}".format(availablefiles[selectionmade]))
                        else:
                            print("{}\n".format(before_swcheck_dict[selectionmade]))
                    except KeyError:
                        print("\nInvalid Response, please enter a valid entry or type 'exit'\n")
            else:
                print("No entries found in the file")
                return
        else:
            file = open(filename, "r")
            print(file.read())
                # iplist.append(ip.rstrip())
            file.close()

    def single_search(self,ipaddr):
        try: #wrapping to keep multiprossesing safer
            #TODO Added SwitchStructure grabbing
            ExitOut = False #temporary boolean to control exiting out of things while still writing

            if self.subs.ping_check(ipaddr):
                if 'apply' in self.cmdargs and self.cmdargs.apply:
                    print("Now performing Full Operation on {}".format(ipaddr))
                else:
                    print("Now performing Check Operation on {}".format(ipaddr))

               #if compare flag is set, populate before dict with provided file, if not grab from switch
                if 'compare' in self.cmdargs and self.cmdargs.compare is not None:
                    with open(os.path.join(self.cmdargs.compare), "rb") as myNewFile:
                        before_swcheck_dict = pickle.load(myNewFile)
                else:
                    before_swcheck_dict = {"ip": ipaddr}
                    #Grabs a snapshot of the switch, not currently used for anything but archival
                    #TODO UNCOMMENT!
                    before_swcheck_dict["SwitchStatus"] = self.subs.snmp_get_switch_data_full(ipaddr)
                    print("ping response for {}, grabbing data".format(ipaddr))

                # TODO: add something to map out attached connections in the ip list, to prevent reloading an upstream

                    try:
                        #test = self.subs.snmp_get_mac_table_bulk(self.cmdargs.ipaddr)
                        #test1 = self.subs.snmp_get_switch_data_full(self.cmdargs.ipaddr)
                        net_connect = self.subs.create_connection(ipaddr)
                        if net_connect:
                            # Show Interface Status
                            #output = net_connect.send_command('show mac address-table ')
                            net_connect.send_command('term shell 0')
                            before_swcheck_dict["sw_raw"] = net_connect.send_command('show switch')
                            before_swcheck_dict["sw_list"] = re.findall(r'''(\d+)(?:\s+) #Switch Number [x][0]
                                                                         (?:\S+)(?:\s+) #Role <ignore this for now>
                                                                         (\S+)(?:\s+) #MAC [x][1]
                                                                         (?:\d+)(?:\s+) #Priority <ignore this for now>
                                                                         (?:\S+)(?:\s+) #HW Version <ignore this for now>
                                                                         (\S+) #Status [x][2]                                                                     
                                                                         ''', before_swcheck_dict["sw_raw"],
                                                      re.VERBOSE | re.MULTILINE)
                            before_swcheck_dict["snoop_raw"] = net_connect.send_command('show ip dhcp snooping binding')
                            before_swcheck_dict["snoop_list"] = re.findall(r'''(^\S+)(?:\s+) #MAC Address [x][0]
                                                                         (\S+)(?:\s+\S+\s+\S+\s+) #IP Address [x][1]
                                                                         (\d+)(?:\s+) #Vlan [x][2]
                                                                         (\S+) #Interface [x][3]                                                                     
                                                                         ''', before_swcheck_dict["snoop_raw"],
                                                      re.VERBOSE | re.MULTILINE)

                            before_swcheck_dict["mac_raw"] = net_connect.send_command('show mac address | exclude CPU')
                            before_swcheck_dict["mac_list"] = re.findall(r'''(?:\s+)(\d+) #Vlan Number [x][0]
                                                                         (?:\s+)(\S+) #MAC Address [x][1]
                                                                         (?:\s+)(?:\S+) #Status [x][2]
                                                                         (?:\s+)(\S+) #SPort [x][3]                                                                     
                                                                         ''', before_swcheck_dict["mac_raw"],
                                                      re.VERBOSE | re.MULTILINE)

                            before_swcheck_dict["ints"] = net_connect.send_command('show int status')
                            before_swcheck_dict["ver"] = net_connect.send_command('show ver | include Software')
                            before_swcheck_dict["cdp"] = net_connect.send_command('show cdp neigh')

                            #grab some before specific info to check before reload
                            #TODO add direct error checking for these values
                            # and interacting here to verify that things are setup correctly before reload
                            net_connect.enable()  # move this out of the if/else statements
                            output = net_connect.send_command('term shell')

                            before_swcheck_dict["flash"] = net_connect.send_command('show flash:')
                            before_swcheck_dict["boot"] = net_connect.send_command('show boot')
                            #TODO grab from boot file what the config file is rather than hard setting packages.conf
                            before_swcheck_dict["packages.conf"] = net_connect.send_command('cat packages.conf')
                            sh_ver = net_connect.send_command('show ver')  # local
                            # TODO Check if gateway on same range as mangement address, use regex
                            before_swcheck_dict["gateway"] = net_connect.send_command('show run | include default-gateway')
                            self.subs.verbose_printer("Switch {}, Current Gateway is {}".format(before_swcheck_dict["ip"],
                                                                                                before_swcheck_dict[
                                                                                                    "gateway"]))

    ################################# Check flash below  ############################
                        #if 'skip' in self.cmdargs and not self.cmdargs.skip:
                        if 'skip' in self.cmdargs and not self.cmdargs.skip and "4500" not in sh_ver and "2950T" not in sh_ver:
                            #TODO 2950T & 4500s will crash here due to the format of their show ver output.
                            before_swcheck_dict["master"] = re.findall(r'^\*\s+(\d)', sh_ver,re.MULTILINE)[0]

                            #create the list that holds the parsed show version file
                            if any(n in sh_ver for n in ["3650","9300", "9200"]):
                                show_version = re.findall(r'''(?:\s+)(\d) #Switch Number [x][0]
                                                                             (?:\s+)(\d{1,2}) #Ports [x][1]
                                                                             (?:\s+)(\S+) #Model [x][2]
                                                                             (?:\s+)(\S+) #SW Version [x][3]
                                                                             (?:\s+)(\S+) #SW VImage [x][4]
                                                                             (?:\s+)(INSTALL|BUNDLE) #Mode[x][5]
                                                                             ''', sh_ver, re.VERBOSE | re.MULTILINE)
                            else:
                                show_version = re.findall(r'''(?:\s+)(\d) #Switch Number [x][0]
                                                                             (?:\s+)(\d{1,2}) #Ports [x][1]
                                                                             (?:\s+)(\S+) #Model [x][2]
                                                                             (?:\s+)(\S+) #SW Version [x][3]
                                                                             (?:\s+)(\S+) #SW VImage [x][4]                                                                         
                                                                             ''', sh_ver, re.VERBOSE | re.MULTILINE)
                            #address the flash filename differences between 3650s and older models
                            sh_flash = net_connect.send_command('show flash?')  # local
                            if any(n in show_version[0][2] for n in ["3650", "C9"]):
                                reg_flash = re.compile(r'flash\-\d\:')  # local
                            else:
                                reg_flash = re.compile(r'flash\d\:')  # local
                            flashes = reg_flash.findall(sh_flash)  # local
                            before_swcheck_dict["curVer"] = ""
                            if flashes: # if there are multiple switches in the stack
                                if any(n in show_version[0][2] for n in ["3650", "C9"]):
                                    # loop through each of the switches
                                    for f in flashes:
                                        x = int(f[-2])-1 #get switch number from flash-x
                                        if x < len(show_version): #this should ignore provisioned switches
                                            self.subs.verbose_printer(
                                                '{} switch-{} current ver: {} {} {}'.format(before_swcheck_dict["ip"],
                                                                                            str(show_version[x][0]),
                                                                                            str(show_version[x][3]),
                                                                                            str(show_version[x][4]),
                                                                                            str(show_version[x][5])))
                                            before_swcheck_dict["curVer"] += "\nSw#{}, Ver:{}, Mode:{}".format(
                                                str(show_version[x][0]), str(show_version[x][3]), str(show_version[x][5]))
                                            #TODO grab the boot file to verify what will be booted
                                            #TODO compare this packages.conf file to the
                                            packages = net_connect.send_command('cat ' + f + 'packages.conf')
                                            ##TODO UNCOMMENT!
                                            before_swcheck_dict["{}fschk".format(f)] = self.sw_3650_precheck(net_connect, f,
                                                                                                        before_swcheck_dict, packages)
                                            if (packages == before_swcheck_dict["packages.conf"]):
                                                self.subs.verbose_printer(
                                                    "{} {} packages.conf is identical to master switch".format(before_swcheck_dict["ip"], f))
                                                if (before_swcheck_dict["{}fschk".format(f)]): # check if flash verified successfully
                                                    self.subs.verbose_printer(
                                                        "{} {} flash verification successful".format(before_swcheck_dict["ip"], f))
                                                    #TODO placeholder, add logic?, print regardless of verbose?
                                                else:
                                                    self.subs.verbose_printer(
                                                        "{} {} flash verification failed".format(before_swcheck_dict["ip"], f))
                                                    ExitOut = True
                                            else:
                                                self.subs.verbose_printer(
                                                    "{} {} packages.conf is different than master".format(before_swcheck_dict["ip"], f))
                                                ExitOut = True
                                            before_swcheck_dict[f] = net_connect.send_command('show ' + f)
                                else: # if it is not a 3650, or 9000 model catalyst
                                    pass ###########everything under this was indented more
                                    # before_swcheck_dict["curVer"] += "\nSw#{}, Ver:{}".format(
                                    #     str(show_version[0][0]), str(show_version[0][3]))
                                    # loop through each of the switches
                                    #################################################*******


                                    #Check to see if all selected boot variables and boot config names are the same
                                    boottest = re.findall(r'^BOOT path-list\s+:\s+flash:(\S+)', before_swcheck_dict["boot"],
                                                          re.MULTILINE)
                                    if boottest.count(boottest[0]) == len(boottest):
                                        self.subs.verbose_printer(
                                            '{} all boot files match: {}'.format(before_swcheck_dict["ip"],boottest[0]))
                                        boottest = re.findall(r'^Config file\s+:\s+flash:(\S+)',
                                                              before_swcheck_dict["boot"],
                                                              re.MULTILINE)
                                        if boottest.count(boottest[0]) == len(boottest):
                                            self.subs.verbose_printer(
                                                '{} all boot config filenames match: {}'.format(before_swcheck_dict["ip"],
                                                                                     boottest[0]))
                                        else:
                                            self.subs.verbose_printer(
                                                "{} switch boot config filenames are not identical".format(
                                                    before_swcheck_dict["ip"]))
                                            ExitOut = True
                                    else:
                                        self.subs.verbose_printer(
                                            "{} switch boot files are not identical".format(before_swcheck_dict["ip"]))
                                        ExitOut = True


                                    if not ExitOut:
                                        for f in flashes:

                                            x = int(f[-2]) - 1  # get switch number from flash-x
                                            self.subs.verbose_printer(
                                                '{} switch-{} current ver: {} {}'.format(before_swcheck_dict["ip"],
                                                                                            str(show_version[x][0]),
                                                                                            str(show_version[x][3]),
                                                                                            str(show_version[x][4])))
                                            before_swcheck_dict["curVer"] += "\nSw#{}, Ver:{}".format(
                                                str(show_version[x][0]), str(show_version[x][3]))

                                            before_swcheck_dict["{}fschk".format(f)] = self.basic_sw_precheck(net_connect, f,
                                                                                                              before_swcheck_dict)

                                            if (before_swcheck_dict["{}fschk".format(f)]):  # check if flash verified
                                                self.subs.verbose_printer(
                                                    "{} {} flash verification successful".format(before_swcheck_dict["ip"],
                                                                                                 f))
                                                # TODO placeholder, add logic?, print regardless of verbose?
                                            else:
                                                self.subs.verbose_printer(
                                                    "{} {} flash verification failed".format(before_swcheck_dict["ip"], f))
                                                ExitOut = True
                                            before_swcheck_dict[f] = net_connect.send_command('show ' + f)
#End of processing multiple switches
                            else: # if only a single switch
                                if any(n in show_version[0][2] for n in ["3650", "C9"]):
                                    self.subs.verbose_printer(
                                        '{} current ver: {} {} {}'.format(before_swcheck_dict["ip"],
                                                                          str(show_version[0][3]),
                                                                          str(show_version[0][4]),
                                                                          str(show_version[0][5])))
                                    before_swcheck_dict["curVer"] += "\nSw#{}, Ver:{}, Mode:{}".format(
                                        str(show_version[0][0]), str(show_version[0][3]), str(show_version[0][5]))

                                    # TODO grab the boot file to verify what will be booted
                                    # TODO compare this packages.conf file to the
                                    packages = net_connect.send_command('cat flash:packages.conf')
                                    # before_swcheck_dict["flash:fschk"] = self.sw_precheck(net_connect, "flash:",
                                    #                                                             before_swcheck_dict, packages)
                                    if self.sw_3650_precheck(net_connect, "flash:", before_swcheck_dict, packages):
                                        self.subs.verbose_printer(
                                            "{} flash verification successful".format(before_swcheck_dict["ip"]))
                                    else:
                                        self.subs.verbose_printer(
                                            "{} flash verification failed".format(before_swcheck_dict["ip"]))
                                        ExitOut = True
                                else:
                                    self.subs.verbose_printer(
                                        '{} switch-{} current ver: {} {}'.format(before_swcheck_dict["ip"],
                                                                                    str(show_version[0][0]),
                                                                                    str(show_version[0][3]),
                                                                                    str(show_version[0][4])))
                                    before_swcheck_dict["curVer"] += "\nSw#{}, Ver:{}".format(
                                        str(show_version[0][0]), str(show_version[0][3]))

                                    before_swcheck_dict["flash:fschk"] = self.basic_sw_precheck(net_connect, "flash:",
                                                                                                      before_swcheck_dict)

                                    if (before_swcheck_dict["flash:fschk"]):  # check if flash verified
                                        self.subs.verbose_printer(
                                            "{} flash verification successful".format(before_swcheck_dict["ip"]))
                                        # TODO placeholder, add logic?, print regardless of verbose?
                                    else:
                                        self.subs.verbose_printer(
                                            "{} flash verification failed".format(before_swcheck_dict["ip"])) #redundant
                                        ExitOut = True

                            if not ExitOut: # redundant?
                                # self.subs.verbose_printer(
                                #     "{} flash checking verification is successful".format(before_swcheck_dict["ip"]))


                                if any(n in show_version[0][2] for n in ["3650", "C9"]):
                                    print("***{} 3650/9300 flash checking verification successful***".format(
                                        before_swcheck_dict["ip"]))
                                    before_swcheck_dict["newVer"] = \
                                    re.findall(r'(?:rp_base\s+)(cat\S+)', before_swcheck_dict["packages.conf"])[0]
                                    #re.findall(r'(?:guestshell\s+)(cat\S+)', before_swcheck_dict["packages.conf"])[0]
                                else:
                                    print("***{} non 3650/9300 flash checking verification successful***".format(
                                        before_swcheck_dict["ip"]))
                                    before_swcheck_dict["newVer"] = \
                                    re.findall(r'^BOOT path-list\s+:\s+flash:(\S+)', before_swcheck_dict["boot"],
                                               re.MULTILINE)[0]


                                before_swcheck_dict["flash_error_bool"] = False # redundant?
                                # print('This switch will reload into ' + str(guestshell))
                            else:
                                print("***{} flash checking verification failed***".format(before_swcheck_dict["ip"]))
                                before_swcheck_dict["flash_error_bool"] = True # redundant?
                ################################# Flash Checking ^^^############################
                        # TODO fix placeholder for curVer & newVer for skipping flag
                        if 'skip' in self.cmdargs and self.cmdargs.skip:
                            before_swcheck_dict['curVer'] = before_swcheck_dict['ver']
                            before_swcheck_dict['newVer'] = before_swcheck_dict['boot']
                            #TODO END placeholder
                        #reload if the apply flag is set, and flash verified successfully
                        if 'apply' in self.cmdargs and self.cmdargs.apply and not ExitOut:
                            output = net_connect.send_command_timing('wr mem')
                            if "confirm" in output:
                                output += net_connect.send_command_timing("y", strip_prompt=False, strip_command=False)
                            # output = net_connect.send_command('wr mem') #failing on prompt where nvram was saved on old ver
                            print("***{}, reloading***".format(ipaddr))
                            if 'delay' in self.cmdargs and self.cmdargs.delay is not None:
                                reload_delay = self.cmdargs.delay
                                # reload_string = "reload in {}\n".format(self.cmdargs.delay)
                            else:
                                reload_delay = "1"
                                # reload_string = "reload in {}\n".format("1")

                            output = net_connect.send_command('reload in {}'.format(reload_delay), expect_string='confirm')
                            # output = net_connect.send_command_timing('reload in {}'.format(reload_delay))
                            if "confirm" in output:
                                output += net_connect.send_command_timing("\n", strip_prompt=False, strip_command=False)

                        elif ExitOut:
                            print("***{}, ERROR!!! pre-check errors encountered. exiting out ***".format(ipaddr))
                        else:

                            print("***{}, Current Version:{} ***".format(ipaddr,
                                                                                             before_swcheck_dict['curVer']))
                            print("***{}, Booting Version:{} ***".format(ipaddr,
                                                                                             before_swcheck_dict['newVer']))
                            print("***{}, status grabbed, NO pre-check errors encountered. exiting out ***".format(ipaddr))

                        # Close Connection
                        net_connect.disconnect()
                        # netmiko connection error handling
                    except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                        self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
                    except netmiko.ssh_exception.NetMikoTimeoutException as err:
                        self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
                    except ValueError as err:
                        print(err.args[0])
                    except Exception as err: #currently a catch all to stop linux from having a conniption when reloading
                        print("NETMIKO ERROR {}:{}".format(ipaddr,err.args[0]))

                    # grab 'after' data to compare with before (if performing reload or comparing with file)
                if ('apply' in self.cmdargs and self.cmdargs.apply and not ExitOut) or ('compare' in self.cmdargs and self.cmdargs.compare is not None):
                    after_swcheck_dict = {"ip": ipaddr}
                    # Grabs a snapshot of the switch, not currently used for anything but archival
                    #perform reload if apply flag is set
                    if 'apply' in self.cmdargs and self.cmdargs.apply:
                        if 'updateinterval' in self.cmdargs and self.cmdargs.updateinterval is not None:
                            update_interval = int(self.cmdargs.updateinterval)
                        else:
                            update_interval = 30
                        mins_waited = 80
                        time.sleep(70)
                        while not self.subs.ping_check(ipaddr):
                            time.sleep(update_interval)
                            print("no response from {}, waited {} seconds (equal to {} minutes) ".format(ipaddr,mins_waited,mins_waited/60))
                            mins_waited += update_interval
                            # if waiting longer than one hour, exit out?
                            if mins_waited > 3600 :
                                #TODO Add writing to log file here?
                                print("No reply from switch IP:{}: for {} minutes\n Please investigate!".format(ipaddr,mins_waited/60))
                                status_dict = {"ip": ipaddr, "Print_Sum": "ERROR - Device did not respond after reload",
                                               "summary": "ERROR - Device did not respond after reload"}
                                return status_dict
                                #sys.exit(1)

                        if self.subs.ping_check(ipaddr): # unnecessary test?
                            print("switch: {} is back online!".format(ipaddr))
                            time.sleep(90) # added a little sleep to give some time for connections to come up
                            after_swcheck_dict["seconds_to_reload"] = mins_waited

                    try:
                        after_swcheck_dict["SwitchStatus"] = self.subs.snmp_get_switch_data_full(ipaddr)
                        net_connect = self.subs.create_connection(ipaddr)
                        if net_connect:
                            net_connect.send_command('term shell 0')
                            after_swcheck_dict["sw_raw"] = net_connect.send_command('show switch')
                            after_swcheck_dict["sw_list"] = re.findall(r'''(\d+)(?:\s+) #Switch Number [x][0]
                                                                          (?:\S+)(?:\s+) #Role <ignore this for now>
                                                                          (\S+)(?:\s+) #MAC [x][1]
                                                                          (?:\d+)(?:\s+) #Priority <ignore this for now>
                                                                          (?:\S+)(?:\s+) #HW Version <ignore this for now>
                                                                          (\S+) #Status [x][2]                                                                     
                                                                          ''', after_swcheck_dict["sw_raw"],
                                                                        re.VERBOSE | re.MULTILINE)
                            if 'apply' in self.cmdargs and self.cmdargs.apply:
                                # Compare the show Switch first (to verify stack members)
                                loopcount = 0
                                #loop up to 36 times to give all stack members time to boot, after that, continue on.
                                while (before_swcheck_dict["sw_list"].sort() != after_swcheck_dict["sw_list"].sort()) and loopcount < 15:
                                #while before_swcheck_dict["sh_sw"] != after_swcheck_dict["sh_sw"] and loopcount<36:
                                    time.sleep(10)
                                    after_swcheck_dict["sw_raw"] = net_connect.send_command('show switch')
                                    after_swcheck_dict["sw_list"] = re.findall(r'''(\d+)(?:\s+) #Switch Number [x][0]
                                                                              (?:\S+)(?:\s+) #Role <ignore this for now>
                                                                              (\S+)(?:\s+) #MAC [x][1]
                                                                              (?:\d+)(?:\s+) #Priority <ignore this for now>
                                                                              (?:\S+)(?:\s+) #HW Version <ignore this for now>
                                                                              (\S+) #Status [x][2]                                                                     
                                                                              ''', after_swcheck_dict["sw_raw"],
                                                                            re.VERBOSE | re.MULTILINE)
                                    loopcount+=1
                            #grab additional information from the switch
                            after_swcheck_dict["snoop_raw"] = net_connect.send_command('show ip dhcp snooping binding')
                            after_swcheck_dict["snoop_list"] = re.findall(r'''(^\S+)(?:\s+) #MAC Address [x][0]
                                                                         (\S+)(?:\s+\S+\s+\S+\s+) #IP Address [x][1]
                                                                         (\d+)(?:\s+) #Vlan [x][2]
                                                                         (\S+) #Interface [x][3]                                                                     
                                                                         ''', after_swcheck_dict["snoop_raw"],
                                                      re.VERBOSE | re.MULTILINE)
                            after_swcheck_dict["mac_raw"] = net_connect.send_command('show mac address | exclude CPU')
                            after_swcheck_dict["mac_list"] = re.findall(r'''(?:\s+)(\d+) #Vlan Number [x][0]
                                                                                                 (?:\s+)(\S+) #MAC Address [x][1]
                                                                                                 (?:\s+)(?:\S+) #Status [x][2]
                                                                                                 (?:\s+)(\S+) #SPort [x][3]                                                                     
                                                                                                 ''',
                                                                         after_swcheck_dict["mac_raw"],
                                                                         re.VERBOSE | re.MULTILINE)
                            after_swcheck_dict["ints"] = net_connect.send_command('show int status')
                            after_swcheck_dict["ver"] = net_connect.send_command('show ver | include Software')
                            after_swcheck_dict["cdp"] = net_connect.send_command('show cdp neigh')

                            # Close Connection
                            net_connect.disconnect()
                        # netmiko connection error handling
                    except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                        self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
                    except netmiko.ssh_exception.NetMikoTimeoutException as err:
                        self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
                    except ValueError as err:
                        # if 'verbose' in self.cmdargs and self.cmdargs.verbose:
                        print(err.args[0])
                    except Exception as err:  # currently a catch all
                        print("NETMIKO ERROR {}:{}".format(ipaddr,err.args[0]))

                #create the logpath directory if it doesn't exist
                if not os.path.exists(self.config.logpath):
                    os.makedirs(self.config.logpath)

                #only create the before file if not loading from a file
                if 'compare' in self.cmdargs and self.cmdargs.compare is None:
                    with open(os.path.join(self.config.logpath, ipaddr + "-Before.txt"), "wb") as myFile:
                        pickle.dump(before_swcheck_dict, myFile)

                #perform the compare on the two files to create a comparison dict (status_dict)
                if ('apply' in self.cmdargs and self.cmdargs.apply and not ExitOut) or ('compare' in self.cmdargs and self.cmdargs.compare is not None):
                    status_dict = {"ip": ipaddr}
                    status_dict["summary"] = ""
                    if "seconds_to_reload" in after_swcheck_dict:
                        status_dict["summary"] += str(after_swcheck_dict['seconds_to_reload']) + " seconds to reload\n"
                    # status_dict["summary"] += "Before Version:{}\nAfter Version:{}\n".format(before_swcheck_dict["ver"],
                    #                                                                        after_swcheck_dict["ver"])

                    # Compare SwitchStruct variables - Version
                    b_SwitchOutofOrder = False
                    # create lists to compare versions from the switch structure basic functionality without snmp
                    ver_before_list = []
                    ver_after_list = []
                    #Will work if SNMP connectivity was successful before and after
                    if 'SwitchStatus' in before_swcheck_dict and 'SwitchStatus' in after_swcheck_dict:
                        for switch in before_swcheck_dict['SwitchStatus'].getSwitches():
                            temp_after_sw = after_swcheck_dict['SwitchStatus'].getSwitch(switch.switchnumber)

                            # create lists to format output
                            ver_before_list.append((switch.switchnumber, switch.version))
                            ver_after_list.append((temp_after_sw.switchnumber, temp_after_sw.version))

                            if temp_after_sw.serialnumber != switch.serialnumber:
                                b_SwitchOutofOrder = True
                        status_dict["Version"] = self.var_list_compare(ver_before_list, ver_after_list, "Version",
                                                                       ipaddr)
                    else:
                        #TODO FIX INTERMITTANT ERROR
                        try:
                            for switch in before_swcheck_dict['sw_list']:
                                temp_after_sw_num = [item[1] for item in after_swcheck_dict['sw_list'] if item[0] == switch[0]]
                                if switch[1] != temp_after_sw_num[0]:
                                    b_SwitchOutofOrder = True
                            ver_before_list.append(before_swcheck_dict["ver"])
                            ver_after_list.append(after_swcheck_dict["ver"])
                            status_dict["Version"] = self.var_list_compare(ver_before_list, ver_after_list, "Version",
                                                                           ipaddr)
                        except Exception as err:  # currently a catch all
                            print("Switch Order Check ERROR {}:{}".format(ipaddr, err.args[0]))
                            status_dict["Version"] = "Unsure of Version, issue occurred"


    ############################END CHANGE

                    if b_SwitchOutofOrder:
                        status_dict["summary"] += "\n!#!#!#!#!#!#!# WARNING: Switches are Out of Order!#!#!#!#!#!#!#\n"

                    if "Version entries are the same" in status_dict["Version"]:
                        status_dict["UpgradeStatus"] = "******Switch {} not upgraded******".format(ipaddr)
                    else:
                        status_dict["UpgradeStatus"] = "******Switch {} upgraded******".format(ipaddr)

                    status_dict["summary"] += status_dict["UpgradeStatus"] + "\n"
                    status_dict["summary"] += "Before Version:{}\nAfter Version:{}\n".format(str(ver_before_list),
                                                                                             str(ver_after_list))
                    status_dict["Print_Sum"] = status_dict["summary"]
                    status_dict["summary"] += status_dict["Version"]

                    #Compare String variables
                    for varname in "ver","ints", "cdp":
                        if varname in before_swcheck_dict and varname in after_swcheck_dict:
                            tempstring, status_dict[varname] = self.var_compare(before_swcheck_dict[varname],
                                                                                after_swcheck_dict[varname],
                                                                                varname,
                                                                                ipaddr)
                            status_dict["summary"] += tempstring
                        else:
                            status_dict["summary"] += "################# {} missing in a list ####################\n\n".format(varname)
                    #Compare List variables
                    for varname in "sw_list","mac_list", "snoop_list":
                        if varname in before_swcheck_dict and varname in after_swcheck_dict:
                             status_dict[varname] = self.var_list_compare(before_swcheck_dict[varname],
                                                                                after_swcheck_dict[varname],
                                                                                varname,
                                                                                ipaddr)
                             status_dict["summary"] += status_dict[varname]
                        else:
                            status_dict["summary"] += "################# {} missing in a list ####################\n\n".format(varname)

                    # temp = '\n'.join(', '.join(elems) for elems in after_swcheck_dict["sw_list"])

                    #<TODO add logic to clearly indicate if a switch is missing or removed from the list when it wasn't before>
                    status_dict["Print_Sum"] += "\n".join(', '.join(elems) for elems in after_swcheck_dict["sw_list"]) \
                                                + "\n--------\n" \
                                                + "Snooping Bindings before:" + str(len(before_swcheck_dict["snoop_list"])) \
                                                + "\n" + "Snooping Bindings after:" + str(len(after_swcheck_dict["snoop_list"])) \
                                                + "\n--------\n"
                    status_dict["Print_Sum"] += re.search('cdp \#+\n((.*\n){1,3}?)\#', status_dict["summary"]).group(1)
                    status_dict["Print_Sum"] += "\n******Switch {} log complete******\n\n".format(after_swcheck_dict['ip'])




                    # #create the logpath directory if it doesn't exist
                # if not os.path.exists(self.config.logpath):
                #     os.makedirs(self.config.logpath)
                #
                # #only create the before file if not loading from a file
                # if 'compare' in self.cmdargs and self.cmdargs.compare is None:
                #     with open(os.path.join(self.config.logpath, ipaddr + "-Before.txt"), "wb") as myFile:
                #         pickle.dump(before_swcheck_dict, myFile)

                ####print out summary of verification if not skipping
                if 'skip' in self.cmdargs and not self.cmdargs.skip:
                    flash_check_dict = {"verification": ipaddr} # could just use a string instead
                    #if ExitOut:
                    if "flash_error_bool" in before_swcheck_dict and before_swcheck_dict["flash_error_bool"]:
                        flash_check_dict["verification"] += "\n******Flash Verification Failure******\n"
                    else:
                        flash_check_dict["verification"] += "\n******Flash Verification Successful******\n"
                    for varname in "boot", "gateway", "sw_raw", "curVer", "master", "newVer":
                        if varname in before_swcheck_dict:
                            flash_check_dict["verification"] += "\n******{}******\n{}\n".format(varname,
                                                                                                before_swcheck_dict[
                                                                                                    varname])
                        else:
                            flash_check_dict["verification"] += "\n******{} not found in dictionary******\n".format(varname)
                        #print out logfile of verification for viewing
                    with open(os.path.join(self.config.logpath, ipaddr + "-Verification.txt"), "w") as out:
                        out.write(flash_check_dict["verification"])


                #right now we're creating multiple seperate log files, concatenate in the future

                #create a func_name variable to differentiate log file names
                if 'apply' in self.cmdargs and self.cmdargs.apply:
                    func_name = "-Reload"
                elif ('compare' in self.cmdargs and self.cmdargs.compare is not None):
                    func_name = "-Check"

                if ('apply' in self.cmdargs and self.cmdargs.apply and not ExitOut) or (
                        'compare' in self.cmdargs and self.cmdargs.compare is not None):
                    with open(os.path.join(self.config.logpath, ipaddr + func_name + "-After.txt"), 'wb') as out:
                        pickle.dump(after_swcheck_dict, out)
                    #TODO:only print check if in verbose mode?
                    with open(os.path.join(self.config.logpath, ipaddr + func_name + "-Diff.txt"), 'wb') as out:
                        pickle.dump(status_dict, out)
                    with open(os.path.join(self.config.logpath, ipaddr + func_name + "-Sum.txt"), 'w') as out:
                        out.write(status_dict["summary"])
                    return status_dict

            else:
                print("device {} not reachable".format(ipaddr))
        except Exception as e: # super broad exception
            print("##### {} ERROR in Processing:{} #####".format(ipaddr, e.args[0]))
            status_dict = {"ip": ipaddr,"Print_Sum":"Failure in processing","summary":"Failure in processing"}
            return status_dict

if __name__ == "__main__":
    #TODO:Update this if necessary, or remove
    # #import files to load config and parse CLI
     import config
     import argparse
    #
     config.load_sw_base_conf()
    # parser = argparse.ArgumentParser(description='Navigate mac address tables to find a specified MAC.')
    # parser.add_argument('startip', metavar='IP',
    #                     help='The IP to start looking for the mac address at')
    # parser.add_argument('-i', '--mac', metavar='macaddr', help="A single mac address to search for")
    # parser.add_argument('-b', '--batchfile', metavar='BATCHFILE', help="File with mac address for batch mode")
    # parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    # parser.add_argument('-c', '--csv', help="save to a specified csv file")
    # cmdargs = parser.parse_args()
    # UpgradeChecker = Lefty(cmdargs,config)


