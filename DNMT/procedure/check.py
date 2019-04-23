#!/usr/bin/env python3

#TODO Add Try/Except loops for proper error handling
#TODO flash verification only works with 3650 right now

import re
import sys
import subprocess,platform,os,time,datetime
import difflib
import pickle



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
        #designed for 3650s, will likely not work with others
        #instead of verification should it just check for files in flash:?
        veribool = True

        # TODO automatically grab these from packages.conf
        reg_rp_base = re.compile(r'(?:rp_base\s+)(cat\S+)')
        reg_rp_core = re.compile(r'(?:rp_core\s+)(cat\S+)')
        reg_rp_daemons = re.compile(r'(?:rp_daemons\s+)(cat\S+)')
        reg_rp_iosd = re.compile(r'(?:rp_iosd\s+)(cat\S+)')
        reg_rp_wcm = re.compile(r'(?:rp_wcm\s+)(cat\S+)')
        reg_rp_webui = re.compile(r'(?:rp_webui\s+)(cat\S+)')
        reg_srdriver = re.compile(r'(?:srdriver\s+)(cat\S+)')
        reg_rp_security = re.compile(r'(?:rp_security\s+)(cat\S+)')
        reg_guestshell = re.compile(r'(?:guestshell\s+)(cat\S+)')
        reg_fp = re.compile(r'(?:fp\s+)(cat\S+)')
        #reg_test = re.compile(r'(?:guedtshell\s+)(cat\S+)')

        packages_check = {"rp_base": reg_rp_base.findall(packages),
                          "rp_core": reg_rp_core.findall(packages),
                          "rp_daemons": reg_rp_daemons.findall(packages),
                          "rp_iosd": reg_rp_iosd.findall(packages),
                          "rp_wcm": reg_rp_wcm.findall(packages),
                          "rp_webui": reg_rp_webui.findall(packages),
                          "srdriver": reg_srdriver.findall(packages),
                          "rp_security": reg_rp_security.findall(packages),
                          "guestshell": reg_guestshell.findall(packages),
                          "fp": reg_fp.findall(packages)}


        for f in packages_check:
            #print(f)
            if packages_check[f]:
                verification = net_connect.send_command('Verify {}{} '.format(flashnum,packages_check[f][0]))
                if "ERROR" in verification:
                    veribool=False
                self.subs.verbose_printer("{} {}-{}\n{}".format(before_swcheck_dict["ip"], flashnum,f,verification))
            else:
                veribool = False
                self.subs.verbose_printer("{} {}{} does not exist".format(before_swcheck_dict["ip"],flashnum,f))
        self.subs.verbose_printer("{} {} verification complete".format(before_swcheck_dict["ip"], flashnum))
        return veribool



    def var_compare(self, before_str, after_str, vartext, ipaddr):
        before_list = before_str.splitlines(1)
        after_list = after_str.splitlines(1)
        sumstring = "################# {} {} ####################\n".format(ipaddr,vartext)
        if before_str == after_str:
            sumstring += "{} are the same\n".format(vartext)
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

    def ping_check(self,sHost):
        try:
            output = subprocess.check_output("ping -{} 1 {}".format('n' if platform.system().lower() == "windows" else 'c', sHost), shell=True)
        except Exception as e:
            return False
        return True


    def single_search(self,ipaddr):
        ExitOut = False #temporary boolean to control exiting out of things while still writing

        if self.ping_check(ipaddr):
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
                print("ping response for {}, grabbing data".format(ipaddr))

            # TODO: add something to map out attached connections in the ip list, to prevent reloading an upstream

                try:
                    net_connect = self.subs.create_connection(ipaddr)
                    if net_connect:
                        # Show Interface Status
                        #output = net_connect.send_command('show mac address-table ')
                        net_connect.send_command('term shell 0')
                        before_swcheck_dict["sh_sw"] = net_connect.send_command('show switch')
                        before_swcheck_dict["sh_snoop"] = net_connect.send_command('show ip dhcp snooping binding')
                        before_swcheck_dict["macs"] = net_connect.send_command('show mac address | exclude CPU')
                        before_swcheck_dict["ints"] = net_connect.send_command('show int status')
                        before_swcheck_dict["ver"] = net_connect.send_command('show ver | include Software')
                        before_swcheck_dict["cdp"] = net_connect.send_command('show cdp neigh')

                        #grab some before specific info to check before reload
                        #TODO add direct error checking for these values
                        # and interacting here to verify that things are setup correctly before reload
                        net_connect.enable()  # move this out of the if/else statements
                        output = net_connect.send_command('term shell')
                        before_swcheck_dict["packages.conf"] = net_connect.send_command('cat packages.conf')
                        before_swcheck_dict["flash"] = net_connect.send_command('show flash:')
                        #TODO grab rp_base,rp_core,rp_daemons,rp_iosd,rp_wcm,rp_webui,srdriver,rp_security,guestshell,fp
                        # then check to see if they exist in the flash of each member

################################# Check flash below  ############################
                    if 'skip' in self.cmdargs and not self.cmdargs.skip:
                        stack = []
                        #x = 0
                        sh_flash = net_connect.send_command('show flash?') #local
                        reg_flash = re.compile(r'flash\-\d\:') #local
                        flashes = reg_flash.findall(sh_flash) #local
                        sh_ver = net_connect.send_command('show ver') #local
                        #reg_test = re.compile(r'\*(?:\s+)(\d)(?:\s+\d{1,2}\s+C9\-.*)')
                        # reg_test = re.compile(r'\*\s+(\d)')
                        # tester = reg_test.findall(sh_ver)
                        #before_swcheck_dict["master"] = re.findall(r'\*(?:\s+)(\d)(?:\s+\d{1,2}\s+W|CS|9\-.*)', sh_ver)[0] # not currently used
                        before_swcheck_dict["master"] = re.findall(r'\*\s+(\d)', sh_ver)[0]
                        # show_version = re.findall(r'''(?:\s+)(\d) #Switch Number [x][0]
                        #                                                  (?:\s+)(\d{1,2}) #Ports [x][1]
                        #                                                  (?:\s+)(WS\-.*\w) #Model [x][2]
                        #                                                  (?:\s+)(\d{1,2}\.\S+) #SW Version [x][3]
                        #                                                  (?:\s+)(CAT\S+\s|cat\S+\s) #SW VImage [x][4]
                        #                                                  (INSTALL|BUNDLE) #Mode[x][5]
                        #                                                  ''', sh_ver, re.VERBOSE)
                        #TODO Move universal things out of this loop
                        show_version = re.findall(r'''(?:\s+)(\d) #Switch Number [x][0]
                                                                         (?:\s+)(\d{1,2}) #Ports [x][1]
                                                                         (?:\s+)(\S+) #Model [x][2]
                                                                         (?:\s+)(\S+) #SW Version [x][3]
                                                                         (?:\s+)(\S+) #SW VImage [x][4]
                                                                         (?:\s+)(INSTALL|BUNDLE) #Mode[x][5]
                                                                         ''', sh_ver, re.VERBOSE)
                        before_swcheck_dict["curVer"] = ""
                        #if "3650" or "9300" in show_version[0][2]: # run the flash check if it is a 3650 model
                        if "3650" in show_version[0][2]:  # run the flash check if it is a 3650 model
                            #check to see if there is more than 1 member in the stack
                            if flashes:
                                # loop through each of the switches
                                for f in flashes:
                                    x = int(f[-2])-1 #get switch number from flash-x
                                    #test2 = int(test)+1
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
                            else:
                                self.subs.verbose_printer(
                                    '{} current ver: {} {} {}'.format(before_swcheck_dict["ip"],
                                                                                str(show_version[0][3]),
                                                                                str(show_version[0][4]),
                                                                                str(show_version[0][5])))
                                before_swcheck_dict["curVer"] += "\nSw#{}, Ver:{}, Mode:{}".format(
                                    str(show_version[0][0]), str(show_version[0][3]), str(show_version[0][5]))


                                #TODO grab the boot file to verify what will be booted
                                #TODO compare this packages.conf file to the
                                packages = net_connect.send_command('cat flash:packages.conf')
                                # before_swcheck_dict["flash:fschk"] = self.sw_precheck(net_connect, "flash:",
                                #                                                             before_swcheck_dict, packages)
                                if self.sw_3650_precheck(net_connect, "flash:",before_swcheck_dict, packages):
                                    self.subs.verbose_printer(
                                        "{} flash verification successful".format(before_swcheck_dict["ip"]))
                                else:
                                    self.subs.verbose_printer(
                                        "{} flash verification failed".format(before_swcheck_dict["ip"]))
                                    ExitOut = True
                        else: # if it is not a 3650...
                            before_swcheck_dict["curVer"] += "\nSw#{}, Ver:{}, Mode:{}".format(
                                str(show_version[0][0]), str(show_version[0][3]), str(show_version[0][5]))

                        if not ExitOut: # redundant?
                            # self.subs.verbose_printer(
                            #     "{} flash checking verification is successful".format(before_swcheck_dict["ip"]))
                            print("***{} flash checking verification successful (if 3650)***".format(before_swcheck_dict["ip"]))
                            if "3650" or "9300" in show_version[0][2]:
                                before_swcheck_dict["newVer"] = \
                                re.findall(r'(?:guestshell\s+)(cat\S+)', before_swcheck_dict["packages.conf"])[0]

                            before_swcheck_dict["flash_check_bool"] = True
                            # print('This switch will reload into ' + str(guestshell))
                        else:
                            print("***{} flash checking verification failed***".format(before_swcheck_dict["ip"]))
                            before_swcheck_dict["flash_check_bool"] = False
            ################################# Flash Checking ^^^############################


                    # TODO verify boot variable is good
                    before_swcheck_dict["boot"] = net_connect.send_command('show boot')
                    #TODO Check if gateway on same range as mangement address, use regex
                    before_swcheck_dict["gateway"] = net_connect.send_command('show run | include default-gateway')
                    self.subs.verbose_printer("Switch {}, Current Gateway is {}".format(before_swcheck_dict["ip"],
                                                                                        before_swcheck_dict[
                                                                                            "gateway"]))
                    #reload if the apply flag is set, and flash verified successfully
                    if 'apply' in self.cmdargs and self.cmdargs.apply and not ExitOut:
                        output = net_connect.send_command('wr mem')
                        print("***{}, reloading***".format(ipaddr))
                        output = net_connect.send_command_timing('reload in 1')
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
                #perform reload if apply flag is set
                if 'apply' in self.cmdargs and self.cmdargs.apply:
                    mins_waited = 80
                    time.sleep(70)
                    while not self.ping_check(ipaddr):
                        time.sleep(10)
                        print("no response from {}, waited {} seconds (equal to {} minutes) ".format(ipaddr,mins_waited,mins_waited/60))
                        mins_waited += 10
                        # if waiting longer than one hour, exit out?
                        if mins_waited > 3600 :
                            print("No reply from switch IP:{}: for {} minutes\n Please investigate!".format(ipaddr,mins_waited/60))
                            sys.exit(1)

                    if self.ping_check(ipaddr): # unnecessary test?
                        print("switch: {} is back online!".format(ipaddr))
                        time.sleep(90) # added a little sleep to give some time for connections to come up
                        after_swcheck_dict["seconds_to_reload"] = mins_waited

                try:
                    net_connect = self.subs.create_connection(ipaddr)
                    if net_connect:
                        net_connect.send_command('term shell 0')
                        after_swcheck_dict["sh_sw"] = net_connect.send_command('show switch')
                        if 'apply' in self.cmdargs and self.cmdargs.apply:
                            # Compare the show Switch first (to verify stack members)
                            loopcount = 0
                            #loop up to 36 times to give all stack members time to boot, after that, continue on.
                            while before_swcheck_dict["sh_sw"] != after_swcheck_dict["sh_sw"] and loopcount < 15:
                            #while before_swcheck_dict["sh_sw"] != after_swcheck_dict["sh_sw"] and loopcount<36:
                                time.sleep(10)
                                after_swcheck_dict["sh_sw"] = net_connect.send_command('show switch')
                                loopcount+=1
                        #grab additional information from the switch
                        after_swcheck_dict["sh_snoop"] = net_connect.send_command('show ip dhcp snooping binding')
                        after_swcheck_dict["macs"] = net_connect.send_command('show mac address | exclude CPU')
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

            #perform the compare on the two files to create a comparison dict (status_dict)
            if ('apply' in self.cmdargs and self.cmdargs.apply and not ExitOut) or ('compare' in self.cmdargs and self.cmdargs.compare is not None):
                status_dict = {"ip": ipaddr}
                status_dict["summary"] = ""
                for varname in "ver", "sh_sw", "macs", "ints", "sh_snoop", "cdp":
                    tempstring, status_dict[varname] = self.var_compare(before_swcheck_dict[varname],
                                                                        after_swcheck_dict[varname],
                                                                        varname,
                                                                        ipaddr)
                    status_dict["summary"] += tempstring

            #create the logpath directory if it doesn't exist
            if not os.path.exists(self.config.logpath):
                os.makedirs(self.config.logpath)

            #only create the before file if not loading from a file
            if 'compare' in self.cmdargs and self.cmdargs.compare is None:
                with open(os.path.join(self.config.logpath, ipaddr + "-Before.txt"), "wb") as myFile:
                    pickle.dump(before_swcheck_dict, myFile)

            ####print out summary of verification if not skipping
            if 'skip' in self.cmdargs and not self.cmdargs.skip:
                flash_check_dict = {"verification": ipaddr} # could just use a string instead
                if ExitOut:
                    flash_check_dict["verification"] += "\n******Flash Verification Failure******\n"
                else:
                    flash_check_dict["verification"] += "\n******Flash Verification Successful******\n"
                for varname in "boot", "gateway", "sh_sw", "curVer", "master", "newVer":
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


    def begin(self):
        if self.cmdargs.upgradecheck == 'single' and self.cmdargs.ipaddr:
            result = self.single_search(self.cmdargs.ipaddr)
            #not printing right now!
            if ('apply' in self.cmdargs and self.cmdargs.apply) or(
                    'compare' in self.cmdargs and self.cmdargs.compare is not None):
                if "identical" in result["ver"]:
                    print("******Switch {}  upgraded******".format(result["ip"]))
                else:
                    print("******Switch {}  not upgraded******".format(result["ip"]))
                self.subs.verbose_printer(result["summary"])
        elif self.cmdargs.upgradecheck == 'batch' and self.cmdargs.file:
            iplist = []
            file = open(self.cmdargs.file, "r")
            for ip in file:
                iplist.append(ip.rstrip())
            file.close()
            #pool = Pool(4) # 4 concurrent processes
            pool = Pool(len(iplist))  # 4 concurrent processes
            results = pool.map(self.single_search,iplist)
            #TODO add printout for comparing as well as reload
            if ('apply' in self.cmdargs and self.cmdargs.apply) or (
                    'compare' in self.cmdargs and self.cmdargs.compare is not None):
                for result in results:
                    if "identical" in result["ver"] :
                        print("******Switch {}  upgraded******".format(result["ip"]))
                    else:
                        print("******Switch {}  not upgraded******".format(result["ip"]))
                    self.subs.verbose_printer(result["summary"])
            print("***Batch Done***")



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


