#!/usr/bin/env python3

import re
import sys
import subprocess,platform,os,time,datetime
import getpass
import difflib
import smtplib
import tempfile
import zipfile
from email import encoders
from email.message import EmailMessage
import pickle,bz2 #imports for statchecks

import zipfile #imports for summary filescompression imports






#3rd party imports
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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
        self.log_path = os.path.abspath(os.path.join(os.sep, 'var', 'log', 'dnmt'))
       # self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
        #                                   datetime.date.today().strftime('%Y%m%d'))



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


    def batchrunwrapper(self):
        file = open(self.cmdargs.file, "r")
        for command in file:
            Return_val = subprocess.run(command, shell=True)
        file.close()



    def connectcount_begin(self):
        #Iterate through addresses List
        file = open(self.cmdargs.file, "r")
        for ip in file:
            self.connectcount(ip.rstrip())
        file.close()

    def connectcount(self, ipaddr):
        try:
            # test = self.subs.snmp_get_mac_table_bulk(self.cmdargs.ipaddr)
            # test1 = self.subs.snmp_get_switch_data_full(self.cmdargs.ipaddr)
            net_connect = self.subs.create_connection(ipaddr)
            if net_connect:
                # Show Interface Status
                # output = net_connect.send_command('show mac address-table ')
                net_connect.send_command('term shell 0')
                #before_swcheck_dict = {"ip": ipaddr}
                intlist = []
                desclist = []
                vlanlist = []

                tempvar = net_connect.send_command('show int  | include thernet|Last input')
                lastvar = ""
                for line in tempvar.splitlines():
                    portnum = self.subs.regex_parser_var0(r"Ethernet([0-9]/\d{1,2})", line)
                    if portnum is not None:
                        lastvar = portnum
                    elif lastvar  is not "":
                        innertemp = self.subs.regex_parser_varx(r"Last input (\S+),\s+output (\S+),", line)
                        if innertemp is not None:
                            pass
                            intlist.append((lastvar,innertemp[0],innertemp[1]))
                            lastvar = ""
                    # if (len(lastvar) == 2): #verify that return isn't borked, should get 3 length tuple
                    #    before_swcheck_dict[lastvar] = "test"\
                tempvar = net_connect.send_command('show int desc')
                for line in tempvar.splitlines():
                    interface = self.subs.regex_parser_var0(r"^\S+(\d/\d{1,2})", line)
                    if interface is not None:
                        description = self.subs.regex_parser_var0(r"^\S+\d/\d{1,2}\s+(?:up|down)\s+(?:up|down)\s+(.+)",line)
                        desclist.append((interface,description))
                        # if description is not "" and description is not None:
                        #     description = description.rstrip()

                tempvar = net_connect.send_command('show int status')
                for line in tempvar.splitlines():
                    interface = self.subs.regex_parser_var0(r"^\S+(\d/\d{1,2})", line)
                    if interface is not None:
                        # description = self.subs.regex_parser_var0(r"^\S+\d/\d{1,2}\s+(.+)(?:connected|notconnect)", line)
                        # if description is not "" and description is not None:
                        #     description = description.rstrip()

                        vlan = self.subs.regex_parser_var0(r"(?:connected|notconnect)\s+(\S+)\s+", line)
                        vlanlist.append((interface,vlan))


                net_connect.disconnect()
                # print("Interface,Last input,Last output")
                # for line in intlist:
                #     print("{},{},{}".format(line[0],line[1],line[2]))
                # for line in  desclist:
                #     print("{},{},{}".format(line[0], line[1], line[2]))

                print ("descint,intint,label,vlan,lastinput,lastoutput")
                for descit, intit, vlanit in zip(desclist,intlist,vlanlist):
                    print("{},{},{},{},{},{},{},{}".format(ipaddr,descit[0],intit[0],vlanit[0],vlanit[1],descit[1],intit[1],intit[2]))
                    if descit[0] != intit[0] or descit[0] != vlanit[0]:
                        print("^^^^^^^^^^^^^^^^^^^^^^^ERROR MISMATCHED INTS^^^^^^^^^^^^")
        # netmiko connection error handling
        except netmiko.ssh_exception.NetMikoAuthenticationException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
        except netmiko.ssh_exception.NetMikoTimeoutException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
        except ValueError as err:
            print(err.args[0])
        except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
            print("NETMIKO ERROR {}:{}".format(ipaddr, err.args[0]))



    def dell_snmp_Begin(self):
        #Iterate through addresses List
        file = open(self.cmdargs.file, "r")
        for ip in file:
            self.DellSnmpAdd(ip.rstrip())
        file.close()

    def DellSnmpAdd(self,ipaddr):
        try:
            # test = self.subs.snmp_get_mac_table_bulk(self.cmdargs.ipaddr)
            # test1 = self.subs.snmp_get_switch_data_full(self.cmdargs.ipaddr)
            print(self.cmdargs.snmpstring)
            net_connect = self.subs.create_connection_vendor(ipaddr,"dell_force10_ssh")
            if net_connect:
                net_connect.enable()
                result = net_connect.send_command('show run | include snmp')
                print("#####{} SNMP before #####\n{}".format(ipaddr,result))
                config_command = ["snmp-server community ncgwWR0C ro"]
                result = net_connect.send_config_set(config_command)
                print("#####{} Progress #####\n{}".format(ipaddr,result))
                result = net_connect.send_command('show run | include snmp')
                print("#####{} SNMP after #####\n{}".format(ipaddr,result))
                output = net_connect.send_command_timing('write')
                if "y/n" in output:
                    output += net_connect.send_command_timing("y", strip_prompt=False, strip_command=False)
                    print("#####{} Save Progress #####\n{}".format(ipaddr,output))


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
