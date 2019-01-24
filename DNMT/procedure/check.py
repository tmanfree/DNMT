#!/usr/bin/env python3


import re
import sys
import subprocess,platform,os,time,datetime
import json
import difflib

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
        self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "LOGS", "UpgradeCheck")

    def var_compare(self, before_str, after_str, vartext,ipaddr):
        before_list = before_str.splitlines(1)
        after_list = after_str.splitlines(1)
        print ("################# {} {} ####################".format(ipaddr,vartext))
        if before_str == after_str:
            print("\n{} are the same".format(vartext))
        elif (len(after_list) / len(before_list)) >= 0.8:
            print("\n{} are similar \nOld Entries:{}\nNew Entries:{}".format(vartext,len(before_list), len(after_list)))
            result = difflib.unified_diff(before_list, after_list) # print if in verbose?
            print(''.join(list(result)), end="")
        else:
            print("\n{} are significantly different\nOld Entries:{}\nNew Entries:{}".format(vartext, len(before_list), len(after_list)))
            result = difflib.unified_diff(before_list, after_list)
            print(''.join(list(result)), end="")

    def ping_check(self,sHost):
        try:
            output = subprocess.check_output("ping -{} 1 {}".format('n' if platform.system().lower() == "windows" else 'c', sHost), shell=True)
        except Exception as e:
            return False
        return True

    def single_search(self,ipaddr):
#TODO: Add CDP Neighbour checking
        # ########testing (without reloading)  #######
        #
        # before_swcheck_dict = json.load(open("OldTemp.txt"))
        # after_swcheck_dict = json.load(open("NewTemp.txt"))
        # ########testing (without reloading)  ^^^#######

        print("Now operating on {}".format(ipaddr))
        before_swcheck_dict = {"ip":ipaddr}
        after_swcheck_dict = {"ip": ipaddr}
        #response = os.system("ping " + ipaddr)
        if self.ping_check(ipaddr):
            print("ping response for {}, grabbing data".format(ipaddr))
            response = 1
            # TODO: add something to map out attached connections in the ip list, to prevent reloading an upstream
            # switch first
            #  do stuff here to reload
            ###########################
            try:
                net_connect = self.subs.create_connection(ipaddr)
                if net_connect:
                    # Show Interface Status
                    #output = net_connect.send_command('show mac address-table ')
                    net_connect.send_command('term shell 0')
                    before_swcheck_dict["sh_sw"] = net_connect.send_command('show switch')
                    before_swcheck_dict["sh_snoop"] = net_connect.send_command('show ip dhcp snooping binding')
                    before_swcheck_dict["macs"] = net_connect.send_command('show mac address')
                    before_swcheck_dict["ints"] = net_connect.send_command('show int status')
                    before_swcheck_dict["ver"] = net_connect.send_command('show ver | include Software')
                    before_swcheck_dict["cdp"] = net_connect.send_command('show cdp neigh')

                    net_connect.enable()
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
            time.sleep(70)
############################
            # while response != True:
            #     time.sleep(10)
            #     response = self.ping_check(ipaddr)
            #     print("ping response for {} is {}".format(ipaddr,response))
            while not self.ping_check(ipaddr):
                time.sleep(10)
                #response = self.ping_check(ipaddr)
                print("no response from {}".format(ipaddr))
            if self.ping_check(ipaddr): # unnecessary test?
                print("switch: {} is back online!".format(ipaddr))
                time.sleep(60) # added a little sleep to give some time for connections to come up
                try:
                    net_connect = self.subs.create_connection(ipaddr)
                    if net_connect:
                        # Show Interface Status
                        # output = net_connect.send_command('show mac address-table ')
                        net_connect.send_command('term shell 0')
                        after_swcheck_dict["sh_sw"] = net_connect.send_command('show switch')
                        # Compare the show Switch first (to verify stack members)
                        loopcount = 0
                        while before_swcheck_dict["sh_sw"] != after_swcheck_dict["sh_sw"] and loopcount<36:
                            time.sleep(10)
                            after_swcheck_dict["sh_sw"] = net_connect.send_command('show switch')
                            loopcount+=1
                        #grab additional information from the switch
                        after_swcheck_dict["sh_snoop"] = net_connect.send_command('show ip dhcp snooping binding')
                        after_swcheck_dict["macs"] = net_connect.send_command('show mac address')
                        after_swcheck_dict["ints"] = net_connect.send_command('show int status')
                        after_swcheck_dict["ver"] = net_connect.send_command('show ver | include Software')
                        after_swcheck_dict["cdp"] = net_connect.send_command('show cdp neigh')

                        # compare switch version
                        if before_swcheck_dict["ver"] == after_swcheck_dict["ver"]:
                            print("Switch {} not upgraded".format(ipaddr))
                        else:
                            print("Switch {} version upgraded".format(ipaddr))
                        print("{}\nOld Software:\n{}\nNew Software:\n{}".format(ipaddr, before_swcheck_dict["ver"],
                                                                            after_swcheck_dict["ver"]))

                        # compare mac tables
                        self.var_compare(before_swcheck_dict["macs"], after_swcheck_dict["macs"], "MAC tables", ipaddr)

                        # compare int status
                        self.var_compare(before_swcheck_dict["ints"], after_swcheck_dict["ints"], "interfaces", ipaddr)

                        # compare snooping tables
                        self.var_compare(before_swcheck_dict["sh_snoop"], after_swcheck_dict["sh_snoop"],
                                         "snooping tables", ipaddr)

                        # compare cdp tables
                        self.var_compare(before_swcheck_dict["cdp"], after_swcheck_dict["cdp"],
                                         "cdp neighbours", ipaddr)



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
                #Print to file TODO:print to a proper file, pretty print? Add flag for output not being default

                if not os.path.exists(self.config.logpath):
                    os.makedirs(self.config.logpath)

                outputfilename = datetime.date.today().strftime('%Y%m%d') + "-" + ipaddr

                json.dump(after_swcheck_dict,
                          open(os.path.join(self.config.logpath, outputfilename + "-After.txt"), 'w'))
                json.dump(before_swcheck_dict,
                          open(os.path.join(self.config.logpath, outputfilename + "-Before.txt"), 'w'))

        else:
            print("device {} not reachable".format(ipaddr))


    def begin(self):
        print("test")
        cwd = os.getcwd()
        print(cwd)
        if self.cmdargs.upgradecheck == 'single' and self.cmdargs.ipaddr:
            self.single_search(self.cmdargs.ipaddr)
        elif self.cmdargs.upgradecheck == 'batch' and self.cmdargs.file:
            #TODO:Get Multiprocessing to work!
            iplist = []
            file = open(self.cmdargs.file, "r")
            for ip in file:
                iplist.append(ip.rstrip())
            file.close()
####         add mapping to verify order to reload here            ###

            #self.map(self.single_search,self.njobs,args=iplist)
            pool = Pool(4) # 4 concurrent processes
            results = pool.map(self.single_search,iplist)

            print ("Batch Done")
            # procs=[]
            # for index, number in enumerate(iplist):
            #     proc = Process(target=self.single_search, args=(number,))
            #     procs.append(proc)
            #     proc.start()
            #     proc.join()

            #for proc in procs:
                #proc.join()


            # pool = Pool(processes=2)
            # print(pool.map(self.single_search, iplist))
            # # result = pool.apply_async(self.single_search,iplist)
            # # print(result.get())
            # pool.close()



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


