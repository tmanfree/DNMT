#!/usr/bin/env python3


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
                        net_connect.enable()  # move this out of the if/else statements
                        output = net_connect.send_command('term shell')
                        before_swcheck_dict["packages.conf"] = net_connect.send_command('cat packages.conf')
                        before_swcheck_dict["flash"] = net_connect.send_command('show flash:')
                        before_swcheck_dict["boot"] = net_connect.send_command('show boot')

                        #skip reload if check flag set
                        if 'apply' in self.cmdargs and self.cmdargs.apply:
                            output = net_connect.send_command('wr mem')
                            #output = net_connect.send_command('reload', expect_string='[confirm]')
                            print("{}, reloading".format(ipaddr))
                            #output = net_connect.send_command('reload in 1')
                            output = net_connect.send_command_timing('reload in 1')
                            #output = net_connect.send_command('y') #linux doesn't gracefully accept this
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
            if ('apply' in self.cmdargs and self.cmdargs.apply) or ('compare' in self.cmdargs and self.cmdargs.compare is not None):
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
            if ('apply' in self.cmdargs and self.cmdargs.apply) or ('compare' in self.cmdargs and self.cmdargs.compare is not None):
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

            #right now we're creating 4 seperate log files, concatenate in the future

            #create a func_name variable to differentiate log file names
            if 'apply' in self.cmdargs and self.cmdargs.apply:
                func_name = "-Reload"
            elif ('compare' in self.cmdargs and self.cmdargs.compare is not None):
                func_name = "-Check"

            if ('apply' in self.cmdargs and self.cmdargs.apply) or (
                    'compare' in self.cmdargs and self.cmdargs.compare is not None):
                with open(os.path.join(self.config.logpath, ipaddr + func_name + "-After.txt"), 'wb') as out:
                    pickle.dump(after_swcheck_dict, out)
                #TODO:only print check if in verbose mode?
                with open(os.path.join(self.config.logpath, ipaddr + func_name + "-Diff.txt"), 'wb') as out:
                    pickle.dump(status_dict, out)
                with open(os.path.join(self.config.logpath, ipaddr + func_name + "-Reload-Sum.txt"), 'w') as out:
                    out.write(status_dict["summary"])
                return status_dict

        else:
            print("device {} not reachable".format(ipaddr))


    def begin(self):
        if self.cmdargs.upgradecheck == 'single' and self.cmdargs.ipaddr:
            result = self.single_search(self.cmdargs.ipaddr)
            #not printing right now!
            if ('apply' in self.cmdargs and self.cmdargs.apply) or (
                    'compare' in self.cmdargs and self.cmdargs.compare is not None):
                if result["ver"] != "identical":
                    print("Switch {}  upgraded".format(result["ip"]))
                else:
                    print("Switch {}  not upgraded".format(result["ip"]))
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
                    if result["ver"] != "identical":
                        print("Switch {}  upgraded".format(result["ip"]))
                    else:
                        print("Switch {}  not upgraded".format(result["ip"]))
                    self.subs.verbose_printer(result["summary"])
            print("Batch Done")



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


