#!/usr/bin/env python3

from netmiko import ConnectHandler
import re
import sys

#Howdy Neighbour!

#Recommended usage Lefty 10.0.0.1 1ef6

def create_connection(ipaddr, username, password):
    print('------- CONNECTING to switch {}-------'.format(ipaddr))

    # Switch Parameters
    cisco_sw = {
        'device_type': 'cisco_ios',
        'ip': ipaddr,
        'username': username,
        'password': password,
        'port': 22,
        'verbose': False,
    }
    # zero out next ip. This will be compared to see if there is another switch required to jump into
    # SSH Connection
    net_connect = ConnectHandler(**cisco_sw)
    return net_connect

def normalize_mac( address):
    tmp3 = address.rstrip().lower().translate({ord(":"): "", ord("-"): "", ord(" "): "", ord("."): ""})
    #tmp3 = address.lower().translate({ord(":"): "", ord("-"): "", ord(" "): ""})

    if len(tmp3) % 4 == 0:
        return '.'.join(a + b + c + d for a, b, c, d in
                    zip(tmp3[::4], tmp3[1::4], tmp3[2::4], tmp3[3::4]))  # insert a period every four chars
    else:
        if len(tmp3) < 4:
            return tmp3
        else:
            print("Please enter a mac address in a group of 4")
            sys.exit()

def batch_search(ipaddr,batchfile,username,password):
    maclist = []
    file = open(batchfile, "r")
    for mac in file:
        # have a check for gethostbyname or addr)
        maclist.append(normalize_mac(mac))
    file.close()

    #callfunc(ipaddr,maclist,username,password)
    unified_search(ipaddr,maclist,username,password)


def unified_search(ipaddr, maclist, username,password):

    sw_dict = {}
    #input_vals = {'IP': ipaddr, 'mac': normalize_mac(macaddr)}

    # Regexs
    reg_PC = re.compile(r'( Po\d)')  # Group 0: search for Port Channel
    reg_PC_port = re.compile(r'..(\d/)*\d/\d{1,2}')  # Group 0: Port in port channel (or mac address table)
    reg_mac_addr = re.compile(r'....\.....\.....')  # Group 0: Port in port channel (or mac address table)
    reg_CDP_Phone = re.compile(r'Phone')  # Group 0: Check CDP neigh for Phone
    reg_IP_addr = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Group 0: Check for IP

    # print("IP Address:{}".format(input_vals['IP']))
   # print("MAC Address:{}".format(input_vals['mac']))

    ### START OF LOOOP - loop to the bottom most port that the MAC is found on

    # Switch Parameters
    net_connect = create_connection(ipaddr, username, password)
    # zero out next ip. This will be compared to see if there is another switch required to jump into

    # SSH Connection
    if net_connect:
        for MAC in maclist:
            ### ADD ERROR HANDLING FOR FAILED CONNECTION
            print("-------- CONNECTED --------")

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
                    print("the furthest downstream location is: {} on switch IP:{}".format(port_reg_find.group(0),
                                                                                           ipaddr))
                    print("port info: {}".format(port_info))
                else:
                    # look for an IP address in CDP neighbour
                    reg_find = reg_IP_addr.search(output)
                    # if an IP is found, it is a switch (assuming it isn't an AP)
                    if reg_find :
                        print("Mac {} found on port {}".format(macHolder.group(0), port_reg_find.group(0)))
                        if reg_find.group(0) not in sw_dict.keys():
                            sw_dict.update({reg_find.group(0): []})
                        if MAC not in sw_dict.values():
                            sw_dict[reg_find.group(0)].append(MAC)
                        #ipaddr = reg_find.group(0)  # assign the next IP and continue
                    # no CDP info is there, it should be a client port
                    else:
                        # port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                        print("the furthest downstream location is: {} on switch IP:{}".format(port_reg_find.group(0),                                                                                               ipaddr))
                        print("port info: {}".format(port_info))

                #    print ("output = {}".format(output))
                #    print ("find = {}".format(reg_find))
                #    print ("formatted = {}".format(reg_find.group(0)))


            else:
                print("Mac address not found.")
        # Close Connection
        net_connect.disconnect()
        for addr_key in sw_dict.keys():
            print(sw_dict)
            callfunc(addr_key, sw_dict[addr_key], username, password)
    print("-------- COMPLETE --------")



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
    args = parser.parse_args()
    if 'batchfile' in args and args.batchfile:
        batch_search(args.ipaddr, args.batchfile, config.username, config.password)
    elif 'mac' in args and args.mac:
        unified_search(args.ipaddr, [normalize_mac(args.mac)], config.username, config.password)