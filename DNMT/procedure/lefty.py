#!/usr/bin/env python3
#Howdy Neighbour!

#from netmiko import ConnectHandler
import socket
import dns.resolver
import dns.zone
import netmiko
import re
import sys

#local subroutine import
from DNMT.procedure.subroutines import SubRoutines


class Lefty:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)

  # def switch_check(self):
    #grab info from 1.3.6.1.2.1.1.1.0
    #example: ProCurve J9022A Switch 2810-48G, revision N.11.15, ROM N.10.01 (/sw/code/build/bass(bh2))"
    #example:Cisco IOS Software, C3560 Software (C3560-IPBASEK9-M), Version 12.2(40)SE, RELEASE SOFTWARE (fc3) Copyright (c) 1986-2007 by Cisco Systems, Inc.
    #return a variable that will be assigned: cisco,hp,unknown to be used when creating connections or snmp walking

    def normalize_mac(self, address):
        tmp3 = address.rstrip().lower().translate({ord(":"): "", ord("-"): "", ord(" "): "", ord("."): ""})
        if len(tmp3) % 4 == 0:
            return '.'.join(a + b + c + d for a, b, c, d in
                        zip(tmp3[::4], tmp3[1::4], tmp3[2::4], tmp3[3::4]))  # insert a period every four chars
        else:
            if len(tmp3) < 4:
                return tmp3
            else:
                print("Please enter a mac address in a group of 4")
                sys.exit()


    def begin_search(self):


        if 'batchfile' in self.cmdargs and self.cmdargs.batchfile:
            maclist = []
            file = open(self.cmdargs.batchfile, "r")
            for mac in file:
                maclist.append(self.normalize_mac(mac))
            file.close()
        elif 'mac' in self.cmdargs and self.cmdargs.mac:
            maclist = [self.normalize_mac(self.cmdargs.mac)]
        self.unified_search(maclist)
        self.print_complete()

    def unified_search(self, maclist):

        sw_dict = {}

        # Regexs
        reg_PC = re.compile(r'( Po\d{1,2})')  # Group 0: search for Port Channel
        #reg_PC_port = re.compile(r'..(\d/)*\d/\d{1,2}')  # Group 0: Port in port channel (or mac address table)
        reg_PC_port = re.compile(r'(..(\d{1,2}/)*\d{1,2}/\d+)\(*')  # Group 0: Port in port channel (or mac address table)
        reg_mac_addr = re.compile(r'....\.....\.....')  # Group 0: Port in port channel (or mac address table)
        reg_CDP_Phone = re.compile(r'Phone')  # Group 0: Check CDP neigh for Phone
        reg_IP_addr = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Group 0: Check for IP

        #create a session
        try:
            net_connect = self.subs.create_connection(self.cmdargs.ipaddr) #added this
            if net_connect:
                self.subs.custom_printer("debug", "## DBG - connected to {} ##".self.cmdargs.ipaddr)
                for MAC in maclist:

                    # Show Interface Status
                    output = net_connect.send_command("show mac address-table | i {}".format(MAC))
                    # example output: 2044    0000.AAAA.BBBB    DYNAMIC     Po9
                    macHolder = reg_mac_addr.search(output)

                    if macHolder is not None:

                        # if a port channel then-->
                        if "Po" in output:
                            reg_find = reg_PC.search(output)
                            output = net_connect.send_command(
                                'show etherchannel summary | include {}\('.format(reg_find.group(0)))
                        port_reg_find = reg_PC_port.search(output)
                        #example output: 9      Po9(SU)         LACP      Te1/0/9(P)  Te2/0/9(P)
                        port_info = net_connect.send_command("show int status | i ({}_) ".format(port_reg_find.group(1)))
                        output = net_connect.send_command("show cdp neigh {} detail".format(port_reg_find.group(1)))
                        # check if the cdp neigh information is a phone
                        reg_find = reg_CDP_Phone.search(output)
                        # if it is a phone....
                        if reg_find is not None:
                            self.log_array.append({'location': "MAC:{}, Switch:{}, "
                                                               "Port:{}".format(MAC, self.cmdargs.ipaddr,
                                                                                port_reg_find.group(1)),
                                                   'info': port_info, 'csv': "{},"
                                                                             "{},{},{}".format(MAC, self.cmdargs.ipaddr,
                                                                                               port_reg_find.group(1),
                                                                                               port_info)})
                            self.subs.verbose_printer("for MAC {}, the furthest downstream location is:"
                                      " {} on switch IP:{}\nport info:{}".format(MAC, port_reg_find.group(1),
                                                                   self.cmdargs.ipaddr,port_info),
                                                          "MAC {} was found".format(MAC))
                        else:
                            # look for an IP address in CDP neighbour
                            reg_find = reg_IP_addr.search(output)
                            # if an IP is found, it is a switch (assuming it isn't an AP)
                            if reg_find:
                                self.subs.verbose_printer("Mac {} found on port {}".format(macHolder.group(0),
                                                                                           port_reg_find.group(1)))
                                if reg_find.group(0) not in sw_dict.keys():
                                    sw_dict.update({reg_find.group(0): []})
                                if MAC not in sw_dict.values():
                                    sw_dict[reg_find.group(0)].append(MAC)
                            # no CDP info is there, it should be a client port
                            else:
                                # port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                                # log_array.append("for MAC {}, the furthest downstream location is: {} on switch IP:{}".format(MAC,port_reg_find.group(0),cmdargs.ipaddr))
                                self.log_array.append({'location': "MAC:{}, Switch:{}, "
                                                                   "Port:{}".format(MAC, self.cmdargs.ipaddr,
                                                                                    port_reg_find.group(1)),
                                                       'info': port_info, 'csv': "{},"
                                                                                 "{},{},{}".format(MAC,
                                                                                                   self.cmdargs.ipaddr,
                                                                                                   port_reg_find.group(
                                                                                                       1), port_info)})
                                self.subs.verbose_printer("for MAC {}, the furthest downstream location is:"
                                                          " {} on switch IP:{}\nport info:{}".format(MAC,
                                                         port_reg_find.group(1),self.cmdargs.ipaddr,port_info),
                                                          print("MAC {} was found".format(MAC)))
                    else:
                        print("Mac address {} not found.".format(MAC))
                # Close Connection
                net_connect.disconnect()
                for addr_key in sw_dict.keys():
                    # print(sw_dict)
                    self.cmdargs.ipaddr = addr_key
                    self.unified_search(sw_dict[addr_key])
            return True
            # netmiko connection error handling
        except netmiko.ssh_exception.NetMikoAuthenticationException as err:
            self.subs.verbose_printer(err.args[0],"Netmiko Authentication Failure")
        except netmiko.ssh_exception.NetMikoTimeoutException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
        except ValueError as err:
            #if 'verbose' in self.cmdargs and self.cmdargs.verbose:
            print(err.args[0])

    def print_complete(self):
        self.subs.verbose_printer("Job Complete")
        [print("%s\nPort info:%s" % (entry['location'], entry['info'])) for entry in self.log_array]
        if 'csv' in self.cmdargs and self.cmdargs.csv is not None:
            self.subs.verbose_printer("Printing to CSV")
            with open(self.cmdargs.csv, 'w', encoding='utf-8') as f:
                print("MAC,Switch_IP,Port,Info", file=f)
                [print("%s" % (entry['csv']), file=f) for entry in self.log_array]


    def begin_snmp_search(self):
        ipaddrlist = []
        if re.match("(\d{1,3}\.){3}\d{1,3}", self.cmdargs.ipaddr): #if a ipv4 address
            self.subs.custom_printer("debug", "## DBG - source is an IP ##")
            ipaddrlist.append(self.cmdargs.ipaddr)
        # elif re.match("^\S+\s\S+$",self.cmdargs.ipaddr): #a general area for example "coh-tr domain.ca"
        #     self.subs.custom_printer("debug", "## DBG - source is a domain ##")
        #     #############STARTEDIT
        #     try:
        #         searchstring = self.cmdargs.ipaddr.split(' ')
        #         #Grab the name server first
        #         self.subs.custom_printer("debug", "## DBG - search string:{} ##".format(searchstring))
        #         soa_answer = dns.resolver.query(searchstring[0], 'SOA')
        #         self.subs.custom_printer("debug", "## DBG - soa_answer:{} ##".format(soa_answer))
        #         master_answer = dns.resolver.query(soa_answer[0].mname,'A')
        #         self.subs.custom_printer("debug", "## DBG - master answer:{} ##".format(master_answer))
        #         # could skip previous 2 lines by presetting Name server address
        #         z = dns.zone.from_xfr(dns.query.xfr(master_answer[0].address,searchstring[0]))
        #         names = z.nodes.keys()
        #         # names.sort()
        #
        #         for n in names:
        #             self.subs.custom_printer("debug", "## DBG - checking name:{} ##".format(n))
        #             if re.match(searchstring[1], str(n)):
        #                 self.subs.custom_printer("debug", "## DBG - matched on name:{} ##".format(n))
        #                 ipaddrlist.append(socket.gethostbyname((str(n)+"."+searchstring[0])))
        #     except socket.error as e:
        #         print('Failed to perform zone transfer:', e)
        #     except dns.exception.FormError as e:
        #         print('Failed to perform zone transfer:', e)
        #     except Exception as err:
        #         print(err)
        #     ############DONEEDIT
        elif re.match("\S+\.ualberta\.ca",self.cmdargs.ipaddr): # if a hostname
            ipaddrlist.append(socket.gethostbyname(self.cmdargs.ipaddr))
        else:
            file = open(self.cmdargs.ipaddr, "r")
            for ip in file:
                ipaddrlist.append(ip) #add hostnames?
            file.close()





        if 'batchfile' in self.cmdargs and self.cmdargs.batchfile:
            maclist = []
            file = open(self.cmdargs.batchfile, "r")
            for mac in file:
                maclist.append(self.normalize_mac(mac))
            file.close()
        elif 'mac' in self.cmdargs and self.cmdargs.mac:
            maclist = [self.normalize_mac(self.cmdargs.mac)]

        for ipaddr in ipaddrlist:
            self.HP_snmp_search(ipaddr,maclist)
        self.print_complete()


    def HP_snmp_search(self,ipaddr,maclist):
        vendor = self.subs.snmp_get_vendor_string(ipaddr)
        if vendor == "HP":
            foundmaclist = self.subs.snmp_get_mac_id_bulk(ipaddr)
            foundmacintlist = self.subs.snmp_get_mac_int_bulk(ipaddr)

            for searchmac in maclist:
                # finishedmaclist =self.Mac_Check(searchmac,foundmaclist,foundmacintlist,finishedmaclist)
                self.Mac_Check(ipaddr, searchmac, foundmaclist, foundmacintlist)
        else:
            print("Currently only works reliably with HP switches")


    def Mac_Count_Check(self,port,foundmacintlist):
        numberOfMacs = 0
        for macListing in foundmacintlist:
            if macListing['Port'] == port:
                numberOfMacs += 1
        return numberOfMacs

    def Mac_Check(self,ipaddr, searchmac,foundmaclist, foundmacintlist):
        partialmatches = 0
        for foundmac in foundmaclist:
            if foundmac['Mac'] == searchmac:  # Complete Match
                for macint in foundmacintlist:
                    if macint['Id'] == foundmac["Id"]:
                        if self.Mac_Count_Check(macint['Port'],foundmacintlist) > 1:
                            foundType = "Uplink Match"
                        else:
                            foundType = "Complete Match"

                        fullint = self.subs.snmp_get_full_interface(ipaddr,macint['Port'])
                        # finishedmaclist.append({"Mac": foundmac['Mac'], "Port": macint["Port"], "Status": "Complete Match"})
                        self.log_array.append({'location': "MAC:{}, Switch:{}, "
                                                           "Port:{}".format(foundmac['Mac'], ipaddr,
                                                                            fullint),
                                               'info': foundType, 'csv': "{},"
                                                                         "{},{},{}".format(foundmac['Mac'],
                                                                                           ipaddr,
                                                                                           fullint, foundType)})
                        return
            elif searchmac in foundmac['Mac']:
                for macint in foundmacintlist:
                    if macint['Id'] == foundmac["Id"]:
                        fullint = self.subs.snmp_get_full_interface(ipaddr, macint['Port'])
                        # finishedmaclist.append({"Mac": foundmac['Mac'], "Port": macint["Port"], "Status": "Partial Match"})
                        self.log_array.append({'location': "MAC:{}, Switch:{}, "
                                                           "Port:{}".format(foundmac['Mac'], ipaddr,
                                                                            fullint),
                                               'info': "Partial Match", 'csv': "{},"
                                                                                "{},{},{}".format(foundmac['Mac'],
                                                                                                  ipaddr,
                                                                                                  fullint,
                                                                                                  "Partial Match")})
                        partialmatches += 1
        if partialmatches == 0:
            self.log_array.append({'location': "MAC:{}, Switch:{}, "
                                               "Port:{}".format(foundmac['Mac'], ipaddr,
                                                                "NA"),
                                   'info': "MAC not found", 'csv': "{},"
                                                                    "{},{},{}".format(foundmac['Mac'],
                                                                                      ipaddr,
                                                                                      "NA",
                                                                                      "MAC not found")})
        return





    #if being run by itself
if __name__ == "__main__":
    #import files to load config and parse CLI
    import config
    import argparse

    config.load_sw_base_conf()
    parser = argparse.ArgumentParser(description='Navigate mac address tables to find a specified MAC.')
    parser.add_argument('startip', metavar='IP',
                        help='The IP to start looking for the mac address at')
    parser.add_argument('-m', '--mac', metavar='macaddr', help="A single mac address to search for")
    parser.add_argument('-b', '--batchfile', metavar='BATCHFILE', help="File with mac address for batch mode")
    parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    parser.add_argument('-c', '--csv', help="save to a specified csv file")
    cmdargs = parser.parse_args()
    macsearcher = Lefty(cmdargs,config)
    macsearcher.begin_search()


