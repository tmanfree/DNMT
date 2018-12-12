#!/usr/bin/env python3
#Howdy Neighbour!

#from netmiko import ConnectHandler
import netmiko
import re
import sys

class Lefty:
    def __init__(self, args, config):
        # initialize values
        self.log_array = []
        self.args = args
        self.config = config

  # def switch_check(self):
    #grab info from 1.3.6.1.2.1.1.1.0
    #example: ProCurve J9022A Switch 2810-48G, revision N.11.15, ROM N.10.01 (/sw/code/build/bass(bh2))"
    #example:Cisco IOS Software, C3560 Software (C3560-IPBASEK9-M), Version 12.2(40)SE, RELEASE SOFTWARE (fc3) Copyright (c) 1986-2007 by Cisco Systems, Inc.
    #return a variable that will be assigned: cisco,hp,unknown to be used when creating connections or snmp walking



    def create_connection(self):
        if 'verbose' in self.args and self.args.verbose:
            print('------- CONNECTING to switch {}-------'.format(self.args.ipaddr))

        # Switch Parameters
        cisco_sw = {
            'device_type': 'cisco_ios',
            'ip': self.args.ipaddr,
            'username': self.config.username,
            'password': self.config.password,
            'port': 22,
            'verbose': False,
        }
        # SSH Connection
        net_connect = netmiko.ConnectHandler(**cisco_sw)
        return net_connect



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
        if 'batchfile' in self.args and self.args.batchfile:
            maclist = []
            file = open(self.args.batchfile, "r")
            for mac in file:
                maclist.append(self.normalize_mac(mac))
            file.close()
        elif 'mac' in self.args and self.args.mac:
            maclist = [self.normalize_mac(self.args.mac)]
        self.unified_search(maclist)

    def unified_search(self, maclist):

        sw_dict = {}

        # Regexs
        reg_PC = re.compile(r'( Po\d)')  # Group 0: search for Port Channel
        reg_PC_port = re.compile(r'..(\d/)*\d/\d{1,2}')  # Group 0: Port in port channel (or mac address table)
        reg_mac_addr = re.compile(r'....\.....\.....')  # Group 0: Port in port channel (or mac address table)
        reg_CDP_Phone = re.compile(r'Phone')  # Group 0: Check CDP neigh for Phone
        reg_IP_addr = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Group 0: Check for IP

        #create a session
        try:
            net_connect = self.create_connection()
            if net_connect:
                for MAC in maclist:

                    # Show Interface Status
                    output = net_connect.send_command('show mac address-table | i ' + MAC)
                    macHolder = reg_mac_addr.search(output)

                    if macHolder is not None:

                        # if a port channel then-->
                        if "Po" in output:
                            reg_find = reg_PC.search(output)
                            output = net_connect.send_command(
                                'show etherchannel summary | include ' + reg_find.group(0))
                        port_reg_find = reg_PC_port.search(output)
                        # currently the following command gets multiple matches on things like 1/0/1 (11,12,13, etc)
                        port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                        output = net_connect.send_command("show cdp neigh {} detail".format(port_reg_find.group(0)))
                        # check if the cdp neigh information is a phone
                        reg_find = reg_CDP_Phone.search(output)
                        # if it is a phone....
                        if reg_find is not None:
                            self.log_array.append({'location': "MAC:{}, Switch:{}, "
                                                               "Port:{}".format(MAC, self.args.ipaddr,
                                                                                port_reg_find.group(0)),
                                                   'info': port_info, 'csv': "{},"
                                                                             "{},{},{}".format(MAC, self.args.ipaddr,
                                                                                               port_reg_find.group(0),
                                                                                               port_info)})
                            if 'verbose' in self.args and self.args.verbose:
                                print("for MAC {}, the furthest downstream location is:"
                                      " {} on switch IP:{}".format(MAC, port_reg_find.group(0),
                                                                   self.args.ipaddr))
                                print("port info: {}".format(port_info))
                            else:
                                print("MAC {} was found".format(MAC))
                        else:
                            # look for an IP address in CDP neighbour
                            reg_find = reg_IP_addr.search(output)
                            # if an IP is found, it is a switch (assuming it isn't an AP)
                            if reg_find:
                                if 'verbose' in self.args and self.args.verbose:
                                    print("Mac {} found on port {}".format(macHolder.group(0), port_reg_find.group(0)))
                                if reg_find.group(0) not in sw_dict.keys():
                                    sw_dict.update({reg_find.group(0): []})
                                if MAC not in sw_dict.values():
                                    sw_dict[reg_find.group(0)].append(MAC)
                            # no CDP info is there, it should be a client port
                            else:
                                # port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                                # log_array.append("for MAC {}, the furthest downstream location is: {} on switch IP:{}".format(MAC,port_reg_find.group(0),args.ipaddr))
                                self.log_array.append({'location': "MAC:{}, Switch:{}, "
                                                                   "Port:{}".format(MAC, self.args.ipaddr,
                                                                                    port_reg_find.group(0)),
                                                       'info': port_info, 'csv': "{},"
                                                                                 "{},{},{}".format(MAC,
                                                                                                   self.args.ipaddr,
                                                                                                   port_reg_find.group(
                                                                                                       0), port_info)})
                                if 'verbose' in self.args and self.args.verbose:
                                    print("for MAC {}, the furthest downstream location is:"
                                          " {} on switch IP:{}".format(MAC, port_reg_find.group(0), self.args.ipaddr))
                                    print("port info: {}".format(port_info))
                                else:
                                    print("MAC {} was found".format(MAC))
                    else:
                        print("Mac address {} not found.".format(MAC))
                # Close Connection
                net_connect.disconnect()
                for addr_key in sw_dict.keys():
                    # print(sw_dict)
                    self.args.ipaddr = addr_key
                    self.unified_search(sw_dict[addr_key])
            return True
            # netmiko connection error handling
        except netmiko.ssh_exception.NetMikoAuthenticationException as err:
            if 'verbose' in self.args and self.args.verbose:
                print(err.args[0])
            else:
                print("Netmiko Authentication Failure")
        except netmiko.ssh_exception.NetMikoTimeoutException as err:
            if 'verbose' in self.args and self.args.verbose:
                print(err.args[0])
            else:
                print("Netmiko Timeout Failure")
        except ValueError as err:
            #if 'verbose' in self.args and self.args.verbose:
            print(err.args[0])




        # SSH Connection


    def print_complete(self):
        print("Job Complete")
        [print("%s\nPort info:%s" % (entry['location'], entry['info'])) for entry in self.log_array]
        if 'csv' in self.args:
            with open(args.csv, 'w', encoding='utf-8') as f:
                print("MAC,Switch_IP,Port,Info", file=f)
                [print("%s" % (entry['csv']), file=f) for entry in self.log_array]

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
    args = parser.parse_args()
    macsearcher = Lefty(args,config)
    if macsearcher.begin_search():
        macsearcher.print_complete()

