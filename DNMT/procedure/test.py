#!/usr/bin/env python3

import re
import sys
import subprocess,platform,os,time,datetime
import requests

import getpass
import difflib
import smtplib
import tempfile
import zipfile
from email import encoders
from email.message import EmailMessage
import pickle,bz2 #imports for statchecks
import urllib3


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
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Supress the ssl unverified notification
       # self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
        #                                   datetime.date.today().strftime('%Y%m%d'))



    def error_check(self):
        error_dict = {"ip": self.cmdargs.ipaddr}
        intId = self.subs.snmp_get_interface_id(self.cmdargs.ipaddr,self.cmdargs.interface)
        self.subs.verbose_printer("interface ID:{}".format(intId))
        error_dict["input errors"] = self.subs.snmp_get_input_errors_by_id(self.cmdargs.ipaddr,intId)
        error_dict["output errors"] = self.subs.snmp_get_output_errors_by_id(self.cmdargs.ipaddr, intId)
        error_dict["crc errors"] = self.subs.snmp_get_crc_errors_by_id(self.cmdargs.ipaddr, intId)
        for entry in error_dict:
            print("{}:{}".format(entry, error_dict[entry]))




    def command_blaster_begin(self):

        #Make Command List
        commandlist = []
        file = open(self.cmdargs.commandfile, "r")
        for ip in file:
            commandlist.append(ip.rstrip())
        file.close()

        #Iterate through addresses List
        if 'single' in self.cmdargs and self.cmdargs.single:
            vendor = self.subs.snmp_get_vendor_string(self.cmdargs.ipaddrfile.rstrip())
            if vendor == "Cisco":
                device_type = "cisco_ios"
            elif vendor == "HP":
                device_type = "hp_procurve"
            else:
                device_type = "generic_termserver"
            self.Command_Blast(self.cmdargs.ipaddrfile.rstrip(), device_type, self.config.username,
                                                   self.config.password, self.config.enable_pw, 22, commandlist)
            # self.Command_Blast(self.cmdargs.ipaddrfile, commandlist)
        else:
            file = open(self.cmdargs.ipaddrfile, "r")

            ##########Begin
            # summary_list = []
            if 'manual' in self.cmdargs and self.cmdargs.manual:
                row_titles = next(file).split(
                    ',')  # grab the first row (the titles) use these to make the standardize switch call dynamic
                row_titles[len(row_titles) - 1] = row_titles[
                    len(row_titles) - 1].rstrip()  # remove the trailing newline
            ############END
            for ip in file:
                #TODO replace the manual flag with a split length check to see if there are multiple fields
                if ('manual' in self.cmdargs and self.cmdargs.manual and len(
                        row_titles) == 6):  # {IP][Vendor][UN][PW][EN][PORT.split]
                    ip_entry = ip.split(',')
                    if (len(ip_entry) == len(row_titles)):
                        ip_entry[len(ip_entry) - 1] = ip_entry[len(ip_entry) - 1].rstrip()
                        self.Command_Blast(ip_entry[row_titles.index("ip")],
                                                                    ip_entry[row_titles.index("type")],
                                                                    ip_entry[row_titles.index("user")],
                                                                    ip_entry[row_titles.index("pass")],
                                                                    ip_entry[row_titles.index("en")],
                                                                    ip_entry[row_titles.index("port")],
                                                                    commandlist)

                elif 'manual' in self.cmdargs and not self.cmdargs.manual:
                    try:
                        vendor = self.subs.snmp_get_vendor_string(ip.rstrip())
                        if vendor == "Cisco":
                            device_type = "cisco_ios"
                        elif vendor == "HP":
                            device_type = "hp_procurve"
                        else:
                            device_type = "generic_termserver"
                        self.Command_Blast(ip.rstrip(), device_type, self.config.username,
                                                                    self.config.password, self.config.enable_pw, 22,commandlist)
                    except Exception as err:
                        print(err)

                # #############
                # self.Command_Blast(ip.rstrip(), commandlist)
            file.close()



    def Command_Blast(self,ipaddr,vendor,username,password,enable_pw,port,commandlist):
        # SSH Connection
        try:
            # net_connect = self.subs.create_connection(ipaddr)
            # net_connect = ConnectHandler(**cisco_sw)
            if "hp_procurve_telnet" in vendor:
                net_connect = self.subs.create_connection_manual(ipaddr, vendor, username, password, enable_pw,
                                                                 port, "sername", "assword")
            else:
                net_connect = self.subs.create_connection_custom(ipaddr, vendor, username, password, enable_pw, port)

            if net_connect:
                ### ADD ERROR HANDLING FOR FAILED CONNECTION
                print("-------- CONNECTED TO {} --------".format(ipaddr))

                if 'enable' in self.cmdargs and self.cmdargs.enable:
                    if 'manual' in self.cmdargs and self.cmdargs.manual:
                        enable_success = self.subs.vendor_enable_manual(vendor, net_connect, username, password,
                                                                        enable_pw)
                    else:
                        enable_success = self.subs.vendor_enable(vendor, net_connect)
                # test = net_connect.find_prompt()

                for command in commandlist:
                    if 'timing' in self.cmdargs and self.cmdargs.timing:
                        result = net_connect.send_command_timing(command)
                    else:
                        result = net_connect.send_command(command)
                    print("COMMAND:{}\nRESPONSE:{}".format(command,result))
                net_connect.disconnect()
                print("-------- CLOSED CONNECTION TO {} --------".format(ipaddr))
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

    def bad_phone_search_begin(self):
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


    def batch_command_wrapper(self):
        file = open(self.cmdargs.file, "r")
        for command in file:
            Return_val = subprocess.run(command, shell=True)
        file.close()



    def connection_count_begin(self):
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

    def vlan_namer_begin(self):
        # Iterate through addresses List
        if 'apply' in self.cmdargs and self.cmdargs.apply:
            print("Beginning Apply Vlan Naming Operation")
        else:
            print("Beginning Check Vlan Naming Operation")
        file = open(self.cmdargs.file, "r")
        for ip in file:
            try:
                if self.subs.ping_check(ip): #check if reachable first
                    self.Vlan_Namer(ip.rstrip())
                else:
                    print("####{}### ERROR Unable to ping ".format(ip.rstrip()))
            except Exception as err:
                print(err)
        file.close()

    def Vlan_Namer(self, ipaddr):
        vendor = self.subs.snmp_get_vendor_string(ipaddr)
        hostname = self.subs.snmp_get_hostname(ipaddr)
        hostname_split = hostname.split('-')
        if len(hostname_split) > 0:
            building_code = hostname_split[0]
        else:
            raise Exception("##### ERROR - unable to parse building name for {}: #####".format(ipaddr))

        current_vlan_list = self.subs.snmp_get_vlan_database(ipaddr, vendor)
        if len(current_vlan_list) > 0:
            try:
                new_vlan_list = self.Ipam_Rest_Get("https://ipam.ualberta.ca/solid.intranet/rest/vlmvlan_list",
                                                   {"WHERE": "vlmdomain_description like '{}'".format(building_code)})

                if new_vlan_list is None:
                    raise Exception("###{}#### ERROR No entries found for building code:{}".format(ipaddr,building_code))

                #grab new vlan name if in IPAM
                for vlanEntry in current_vlan_list:
                    vlanEntry["NewName"] = next((newvlanEntry['vlmvlan_name'] for newvlanEntry in new_vlan_list if
                                                 newvlanEntry["vlmvlan_vlan_id"] == str(vlanEntry["ID"])), None)

                if 'apply' in self.cmdargs and self.cmdargs.apply:
                    if vendor == "Cisco":
                        net_connect = self.subs.create_connection_vendor(ipaddr, "cisco_ios")
                        result = net_connect.enable()
                    elif vendor =="HP":
                        net_connect = self.subs.create_connection_vendor(ipaddr,"hp_procurve")
                        result = self.subs.hp_connection_enable(net_connect) #TODO ADD error handling here
                    else:
                        net_connect = self.subs.create_connection(ipaddr)
                        result = net_connect.enable()



                    if net_connect:
                        ### ADD ERROR HANDLING FOR FAILED CONNECTION
                        print("-------- PROCESSING {}  --------".format( ipaddr))


                        for vlanEntry in current_vlan_list:
                            if vlanEntry["NewName"] is not None and vlanEntry["NewName"] is not "":
                                if (vlanEntry["NewName"] == vlanEntry["Name"]):
                                    self.subs.custom_printer("verbose", "###{}### vlan {} is the SAME: {} ".format(ipaddr, vlanEntry["ID"],vlanEntry["Name"]))
                                else:
                                    result = net_connect.send_config_set(["vlan {}".format(vlanEntry["ID"]), "name {}".format(vlanEntry["NewName"])])
                                    #self.subs.verbose_printer(result)
                                    #If the names are too long they won't apply, HP Procurve in ASH reporting a limit of 12 characters
                                    print("###{}### vlan {} changed from {} to {}".format(ipaddr, vlanEntry["ID"],
                                                                                          vlanEntry["Name"],
                                                                                          vlanEntry["NewName"]))
                            else:
                                self.subs.custom_printer("verbose", "###{}### vlan {} not found in IPAM. Old Name: {}".format(ipaddr,vlanEntry["ID"],vlanEntry["Name"]) )
                        result = net_connect.save_config()
                        # self.subs.verbose_printer("###{}###   {}".format(ipaddr, result))
                        net_connect.disconnect()
                        print("-------- FINISHED PROCESSING {}  --------\n".format(ipaddr))
                    else:
                        print("-------- FAILED TO CONNECTED TO {} --------\n".format(ipaddr))
                else: #just checking
                    print("-------- CHECKING VLANS ON {}  --------".format(ipaddr))
                    for vlanEntry in current_vlan_list:
                        if vlanEntry["NewName"] is not None and vlanEntry["NewName"] is not "":
                            if (vlanEntry["NewName"] == vlanEntry["Name"]):
                                self.subs.verbose_printer(
                                    "###{}### vlan {} is the SAME: {} ".format(ipaddr, vlanEntry["ID"],
                                                                               vlanEntry["Name"]))
                            else:
                                print("###{}### vlan {} is DIFFERENT. \nOLD: {} \nNEW: {}".format(ipaddr, vlanEntry["ID"],
                                                                                      vlanEntry["Name"],
                                                                                      vlanEntry["NewName"]))
                        else:
                            print("###{}### vlan {} not found in IPAM. Old Name: {}".format(ipaddr, vlanEntry["ID"],
                                                                                            vlanEntry["Name"]))
                    print("-------- FINISHED CHECKING {}  --------\n".format(ipaddr))

            except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
            except netmiko.ssh_exception.NetMikoTimeoutException as err:
                self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
            except ValueError as err:
                print(err.args[0])
            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                print("NETMIKO ERROR {}:{}".format(ipaddr, err.args[0]))


    def Core_Mapper(self, ipaddr):
        try:
            vendor = self.subs.snmp_get_vendor_string(ipaddr)
            # Get CDP information for ports
            cdp_list = self.subs.snmp_get_neighbour_bulk(ipaddr, vendor)

            connected_uplinks = [cdpEntry for cdpEntry, cdpEntry in enumerate(cdp_list) if "corenet" in cdpEntry["Value"]]
            if len(connected_uplinks) > 0:
                vlan_list = self.subs.snmp_get_vlan_database(ipaddr, vendor)
                for uplinkEntry in connected_uplinks:
                    uplinkEntry["LocalPort"] = next((cdpEntry['Value'] for cdpEntry in cdp_list if cdpEntry["Id"] == uplinkEntry['Id'] and cdpEntry["Category"] == 7), None)
                    try:
                        net_connect = self.subs.create_connection(uplinkEntry['Value'])
                        if net_connect:
                            ### ADD ERROR HANDLING FOR FAILED CONNECTION
                            print("-------- CONNECTED TO {} for {} --------".format(uplinkEntry['Value'], ipaddr))
                            for vlanEntry in vlan_list:
                                result = net_connect.send_command("show vlan id {} | include active".format(vlanEntry['ID']))
                                vlanEntry["CoreName"] = self.regex_parser_var0(r"^\d+\s+(\S+)$", result)
                            print(" ID:{} Current Name:{} Core Name:{}".format(vlanEntry["ID"], vlanEntry["Name"], vlanEntry["CoreName"]))


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


                #login to edge switch to get the remote port of the cdp stuff

                #verify which vlans are actually passed to the edge switch
                #Log onto connected core now to get names of connected vlans



            vlan_list =  self.subs.snmp_get_vlan_database(ipaddr, vendor)


        except Exception as err:
            print(err)
        pass

    def Ipam_Rest_Get(self,url,params):

        # url = "https://ipam.ualberta.ca/solid.intranet/rest/vlmvlan_list"
        # params = {"WHERE":"vlmdomain_description like 'VPL' and vlmvlan_vlan_id = 4031"}
        # params = {"WHERE": "vlmdomain_description like '{}'".format(buildingcode)}

        try:

            response = requests.get(url,params,verify=False,auth=(self.config.ipam_un,self.config.ipam_pw))
            #Add error handling
            test = response.json()
            if len(test)>0:
                return test
                # vlanName = next((vlanEntry['vlmvlan_name'] for vlanEntry in test if vlanEntry["vlmvlan_vlan_id"] == vlanid ), None)
                # print("ID:{} NAME:{}".format(vlanid,vlanName))
            else:
                raise Exception('##### ERROR - no return from IPAM: #####')

        except Exception as err:
            print(err)
            # raise Exception(err)
