#!/usr/bin/env python3

from netmiko import ConnectHandler
import re
import sys

global log_array

#Howdy Neighbour!
#Recommended usage Lefty 10.0.0.1 1ef6

def create_connection(args, config):
    if args.verbose:
        print('------- CONNECTING to switch {}-------'.format(args.ipaddr))

    # Switch Parameters
    cisco_sw = {
        'device_type': 'cisco_ios',
        'ip': args.ipaddr,
        'username': config.username,
        'password': config.password,
        'port': 22,
        'verbose': False,
    }
    # SSH Connection
    net_connect = ConnectHandler(**cisco_sw)
    return net_connect

def normalize_mac( address):
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


def batch_search(args,config):
    maclist = []
    file = open(args.batchfile, "r")
    for mac in file:
        maclist.append(normalize_mac(mac))
    file.close()
    unified_search(args ,maclist,config)



def unified_search(args, maclist, config):

    sw_dict = {}

    # Regexs
    reg_PC = re.compile(r'( Po\d)')  # Group 0: search for Port Channel
    reg_PC_port = re.compile(r'..(\d/)*\d/\d{1,2}')  # Group 0: Port in port channel (or mac address table)
    reg_mac_addr = re.compile(r'....\.....\.....')  # Group 0: Port in port channel (or mac address table)
    reg_CDP_Phone = re.compile(r'Phone')  # Group 0: Check CDP neigh for Phone
    reg_IP_addr = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Group 0: Check for IP

    #create a session
    net_connect = create_connection(args, config)

    # SSH Connection
    if net_connect:
        for MAC in maclist:

            # Show Interface Status
            output = net_connect.send_command('show mac address-table | i ' + MAC)
            macHolder = reg_mac_addr.search(output)

            if macHolder is not None:

                # if a port channel then-->
                if "Po" in output:
                    reg_find = reg_PC.search(output)
                    output = net_connect.send_command('show etherchannel summary | include ' + reg_find.group(0))
                port_reg_find = reg_PC_port.search(output)
                # currently the following command gets multiple matches on things like 1/0/1 (11,12,13, etc)
                port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                output = net_connect.send_command("show cdp neigh {} detail".format(port_reg_find.group(0)))
                # check if the cdp neigh information is a phone
                reg_find = reg_CDP_Phone.search(output)
                # if it is a phone....
                if reg_find is not None:
                    log_array.append({'location': "MAC:{}, Switch:{}, "
                                                  "Port:{}".format(MAC, args.ipaddr, port_reg_find.group(0)),
                                      'info': port_info, 'csv': "{},"
                                                                "{},{},{}".format(MAC, args.ipaddr,
                                                                                  port_reg_find.group(0), port_info)})
                    if args.verbose:
                        print("for MAC {}, the furthest downstream location is:"
                              " {} on switch IP:{}".format(MAC,port_reg_find.group(0),
                                                           args.ipaddr))
                        print("port info: {}".format(port_info))
                    else:
                        print ("MAC {} was found".format(MAC))
                else:
                    # look for an IP address in CDP neighbour
                    reg_find = reg_IP_addr.search(output)
                    # if an IP is found, it is a switch (assuming it isn't an AP)
                    if reg_find :
                        if args.verbose:
                            print("Mac {} found on port {}".format(macHolder.group(0), port_reg_find.group(0)))
                        if reg_find.group(0) not in sw_dict.keys():
                            sw_dict.update({reg_find.group(0): []})
                        if MAC not in sw_dict.values():
                            sw_dict[reg_find.group(0)].append(MAC)
                    # no CDP info is there, it should be a client port
                    else:
                        # port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                        #log_array.append("for MAC {}, the furthest downstream location is: {} on switch IP:{}".format(MAC,port_reg_find.group(0),args.ipaddr))
                        log_array.append({'location': "MAC:{}, Switch:{}, "
                                                  "Port:{}".format(MAC, args.ipaddr, port_reg_find.group(0)),
                                          'info': port_info, 'csv': "{},"
                                                                    "{},{},{}".format(MAC, args.ipaddr,
                                                                                  port_reg_find.group(0),port_info)})
                        if args.verbose:
                            print("for MAC {}, the furthest downstream location is:"
                              " {} on switch IP:{}".format(MAC,port_reg_find.group(0),args.ipaddr))
                            print("port info: {}".format(port_info))
                        else:
                            print("MAC {} was found".format(MAC))
            else:
                print("Mac address {} not found.".format(MAC))
        # Close Connection
        net_connect.disconnect()
        for addr_key in sw_dict.keys():
            #print(sw_dict)
            args.ipaddr = addr_key
            unified_search(args, sw_dict[addr_key], config)
    #print("-------- COMPLETE --------")



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
    log_array = []
    if 'batchfile' in args and args.batchfile:
        batch_search(args, config)
    elif 'mac' in args and args.mac:
        unified_search(args, [normalize_mac(args.mac)], config)
    print("Job Complete")
    [print("%s\nPort info:%s" % (entry['location'], entry['info'])) for entry in log_array]
    if 'csv' in args:
        with open(args.csv, 'w', encoding='utf-8') as f:
            print("MAC,Switch_IP,Port,Info", file=f)
            [print("%s" % (entry['csv']), file=f) for entry in log_array]

