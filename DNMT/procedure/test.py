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
       # self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
        #                                   datetime.date.today().strftime('%Y%m%d'))


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

    def Error_Check(self):
        error_dict = {"ip": self.cmdargs.ipaddr}
        intId = self.subs.snmp_get_interface_id(self.cmdargs.ipaddr,self.cmdargs.interface)
        self.subs.verbose_printer("interface ID:{}".format(intId))
        error_dict["input errors"] = self.subs.snmp_get_input_errors_by_id(self.cmdargs.ipaddr,intId)
        error_dict["output errors"] = self.subs.snmp_get_output_errors_by_id(self.cmdargs.ipaddr, intId)
        error_dict["crc errors"] = self.subs.snmp_get_crc_errors_by_id(self.cmdargs.ipaddr, intId)
        for entry in error_dict:
            print("{}:{}".format(entry, error_dict[entry]))

    def Command_Blaster_Begin(self):

        #Make Command List
        commandlist = []
        file = open(self.cmdargs.commandfile, "r")
        for ip in file:
            commandlist.append(ip.rstrip())
        file.close()

        #Iterate through addresses List
        file = open(self.cmdargs.ipaddrfile, "r")
        for ip in file:
            self.Command_Blast(ip.rstrip(), commandlist)
        file.close()



    def Command_Blast(self,ipaddr,commandlist):
        # SSH Connection
        try:
            net_connect = self.subs.create_connection(ipaddr)
            # net_connect = ConnectHandler(**cisco_sw)
            if net_connect:
                ### ADD ERROR HANDLING FOR FAILED CONNECTION
                print("-------- CONNECTED TO {} --------".format(ipaddr))

                for command in commandlist:
                    result = net_connect.send_command(command)
                    print("COMMAND:{}\nRESPONSE:{}".format(command,result))
                net_connect.disconnect()
            else:
                print("-------- FAILED TO CONNECTED TO {} --------".format(ipaddr))
        except netmiko.ssh_exception.NetMikoAuthenticationException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
        except netmiko.ssh_exception.NetMikoTimeoutException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
        except ValueError as err:
            print(err.args[0])
        except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
            print("NETMIKO ERROR {}:{}".format(ipaddr, err.args[0]))

    def BadPhoneBegin(self):
        iplist = []
        file = open(self.cmdargs.file, "r")
        for ip in file:
            iplist.append(ip.rstrip())
        file.close()

        for ip in iplist:
            self.BadPhoneFinder(ip)

    def BadPhoneFinder(self,ipaddr):
        try:
            # test = self.subs.snmp_get_mac_table_bulk(self.cmdargs.ipaddr)
            # test1 = self.subs.snmp_get_switch_data_full(self.cmdargs.ipaddr)
            net_connect = self.subs.create_connection(ipaddr)
            if net_connect:
                sw_dict = {"ip": ipaddr}
                sw_dict["int_return"] = net_connect.send_command('show power inline | include Ieee')
                sw_dict["int_list"] = re.findall('(?:\s*)(\S+)(?:\s+.*)', sw_dict["int_return"], re.VERBOSE | re.MULTILINE)
                if len(sw_dict["int_list"]) is not 0:
                    print("{} --- {} Ieee interfaces found".format(sw_dict["ip"], len(sw_dict["int_list"])))
                    for interface in sw_dict["int_list"]:
                        int_status = net_connect.send_command('show int {}'.format(interface)).split("\n")[0]

                        if "notconnect" in int_status:
                            if 'skip' in self.cmdargs and not self.cmdargs.skip:
                                response = input("{} --- {} is showing NotConnected, toggle port on/off ('yes'):".format(sw_dict["ip"], interface))
                                if not response == 'yes':
                                    self.subs.verbose_printer('Did not proceed with change.')
                                    sys.exit(1)
                            self.subs.snmp_reset_interface(ipaddr,
                                                           self.subs.snmp_get_interface_id(ipaddr,
                                                                                           interface))
                            print("{} --- {} interface restarted".format(sw_dict["ip"], interface))


                        else:
                            print("{} --- {} Port is showing connected".format(sw_dict["ip"],interface))
                else:
                    print("{} --- No Ieee entries found".format(sw_dict["ip"]))


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

