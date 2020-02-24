#!/usr/bin/env python3

#TODO Add Try/Except loops for proper error handling
#TODO flash verification skipping for 4500 & 2950T models
#Warning - Does not work on 4500 or 2950 T models

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



class Tools:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        #self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
        #                                   datetime.date.today().strftime('%Y%m%d'))

    def TDR_Test(self,net_connect,interface):
        net_connect.enable()
        print("performing diagnostic on {}".format(interface))
        result = net_connect.send_command('test cable-diagno tdr interface {}'.format(interface))
        print("waiting for 15 seconds")
        time.sleep(15)
        test_result = net_connect.send_command('show cable-diagnostics tdr int {}'.format(interface))
        print("Results are:\n{}".format(test_result))
        #net_connect.disable() #incorrect syntax

        return



    def Ap_Poke(self):
        #cmdargs.interface
        #cmdargs.ipaddr


        #format interface string:
        self.cmdargs.interface = re.sub('[a-zA-Z]', '', self.cmdargs.interface)

        if self.subs.ping_check(self.cmdargs.ipaddr):
            self.subs.verbose_printer(print(
                "{} Reachable, Now performing AP Poke Operation on {}".format(self.cmdargs.ipaddr,
                                                                              self.cmdargs.interface)))
            if self.cmdargs.login:
                self.config.username = input("Input user name to login to switch:")
                self.config.password = getpass.getpass("Input password to login to switch:")
                self.config.enable_pw = getpass.getpass("Input enable password for switch:")

            try:
                net_connect = self.subs.create_connection(self.cmdargs.ipaddr)

                if net_connect:
                    swcheck_dict = {"ip": self.cmdargs.ipaddr, "interface": self.cmdargs.interface}
                    net_connect.send_command('term shell 0')
                    swcheck_dict["sh_int_status"] = net_connect.send_command(
                        'show int status | include {} .'.format(swcheck_dict["interface"]))
                    #create a variable to grab speed (assuming just a number is passed (1/0/11 for example)
                    # if re.search('[a-zA-Z]', self.cmdargs.interface):
                    #     swcheck_dict["local_int"] = self.cmdargs.interface
                    # else:
                    swcheck_dict["local_int"] = self.subs.regex_parser_var0(r'^(\S+)',swcheck_dict["sh_int_status"])

                    swcheck_dict["sh_int"] = net_connect.send_command(
                        'show int {} | include {} .'.format(swcheck_dict["local_int"], swcheck_dict["interface"]))
                    swcheck_dict["sh_mac"] = net_connect.send_command(
                        'show mac address int {}'.format(swcheck_dict["local_int"]))
                    swcheck_dict["mac_stat"] = \
                        re.findall(r'({}+)'.format(swcheck_dict["interface"]), swcheck_dict["sh_mac"], re.MULTILINE)
                    swcheck_dict["sh_cdp"] = net_connect.send_command(
                        'show cdp neigh {}'.format(swcheck_dict["local_int"]))
                    swcheck_dict["cdp_stat"] = \
                        re.findall(r'entries displayed : (\S+)', swcheck_dict["sh_cdp"], re.MULTILINE)
                    swcheck_dict["sh_power"] = net_connect.send_command(
                        'show power inline | include {} .'.format(swcheck_dict["interface"]))
                    swcheck_dict["power_stat"] = self.subs.regex_parser_var0(r'^(?:\S+\s+\S+\s+\S+\s+\S+\s+)(\S+)',
                                                                             swcheck_dict["sh_power"])
                    swcheck_dict["int_stat"] = self.subs.regex_parser_var0(r'(?:line protocol is )(\S+)',
                                                                           swcheck_dict["sh_int"])
                    swcheck_dict["power_stat"] = self.subs.regex_parser_var0(r'^(?:\S+\s+\S+\s+\S+\s+\S+\s+)(\S+)', swcheck_dict["sh_power"])
                    swcheck_dict["int_stat"] = self.subs.regex_parser_var0(r'(?:line protocol is )(\S+)',swcheck_dict["sh_int"] )


                    self.subs.verbose_printer(
                        "Switch:{}\nInterface:{}\nInt Status:{}\nPower Status:{}\n# of MACs:{}".format(
                            swcheck_dict["ip"], swcheck_dict["local_int"], swcheck_dict["int_stat"],
                            swcheck_dict["power_stat"], len(swcheck_dict["mac_stat"])))

                    # Currently will only work if:
                    # -The port is down (AP may be locked up)
                    # -The port is up with an AP (catches some odd APs behaviour, used on 100M connections)
                    # -The port is up with Ieee and 0 Mac Addresses (AP is locked up)
                    if (swcheck_dict["int_stat"] == "down") or (swcheck_dict["int_stat"] == "up" and (
                            ("AIR" in swcheck_dict["power_stat"]) or (
                            "Ieee" in swcheck_dict["power_stat"] and len(swcheck_dict["mac_stat"]) == 0))):


                        #TODO Add some logic to reload APs if not fincioning correctly
                        if "AIR" in swcheck_dict['sh_cdp']:
                            response = input("Port appears to have a live AP, confirm action of toggling port on/off ('yes'):")
                            if not response == 'yes':
                                self.subs.verbose_printer('Did not proceed with change.')
                                sys.exit(1)

                        print("Change appears safe*") # change mac addresses to be 0,
                        if not self.cmdargs.skip:
                            if self.cmdargs.tdr: #Run a TDR test before if flag is set
                                self.TDR_Test(net_connect,swcheck_dict['local_int'])
                            response = input("Confirm action of toggling port on/off ('yes'):")
                            if not response == 'yes':
                                self.subs.verbose_printer('Did not proceed with change.')
                                sys.exit(1)



                        self.subs.snmp_reset_interface(self.cmdargs.ipaddr,
                            self.subs.snmp_get_interface_id(self.cmdargs.ipaddr,
                                                                     swcheck_dict["local_int"]))
                        # net_connect.enable()
                        # config_command = ["interface " + swcheck_dict["local_int"], "shutdown"]
                        # shutdown_output = net_connect.send_config_set(config_command)
                        # self.subs.verbose_printer('Port Shutdown, waiting 5 seconds.')
                        # time.sleep(5)
                        # config_command = ["interface " + swcheck_dict["local_int"], "no shutdown"]
                        # shutdown_output = net_connect.send_config_set(config_command)
                        # self.subs.verbose_printer('Port Enabled.')

                    else:
                        print("Change may be unsafe, exiting.")
                       # net_connect.send_command('int {}'.format(swcheck_dict["local_int"]))
                       # net_connect.send_command('shutdown')
                    net_connect.disconnect()
            # netmiko connection error handling
            except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
                sys.exit(1)
            except netmiko.ssh_exception.NetMikoTimeoutException as err:
                self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
                sys.exit(1)
            except ValueError as err:
                print(err.args[0])
                sys.exit(1)
            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                print("NETMIKO ERROR {}:{}".format(self.cmdargs.ipaddr, err.args[0]))
                sys.exit(1)
#
#

