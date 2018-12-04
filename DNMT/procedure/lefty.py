#!/usr/bin/env python3

from netmiko import ConnectHandler
import re
import sys

#test
import time





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



# send a list of macs to
def callfunc(ipaddr, maclist, username, password):
    dict = {}

    # Search MAC address table for the interface
    net_connect = create_connection(ipaddr,username,password)
    if net_connect:
        for MAC in maclist:
            output = net_connect.send_command('sh mac address-table | i ' + str(MAC))
            if "Po" in output:
                reg_PC = re.compile(r'( Po\d)')  # Group 0: search for Port Channel
                reg_find = reg_PC.search(output)
                output = net_connect.send_command('show etherchannel summary | include ' + reg_find.group(0))
#            reg_PC_port = re.compile(r'..(\d/)*\d/\d{1,2}')
#            mac_int = reg_PC_port.search(output)  ###change table to output
                reg_mac = re.compile(r'' +  '(?:\s+.*?)' + '((Gi\d\/\d\/\d+)|(Te\d\/\d\/\d+))')
            else:
                reg_mac = re.compile(r'' + ((re.escape(MAC))) + '(?:\s+.*?)' + '((Gi\d\/\d\/\d+)|(Te\d\/\d\/\d+)|(Po\d+))')
            mac_int = reg_mac.search(output)  ###change table to output

            # group 1 contains the interface str
            if mac_int:
                interface = mac_int.group(1)
    #add            interface = mac_int.group(0)
                if interface not in dict.keys():
                    dict.update({interface: []})
                if MAC not in dict.values():
                    dict[interface].append(MAC)
            else:
                print("Mac Address last hop is on switch {}\n {}".format(ipaddr,output))

        # Replace the interface with an IP address from CDP nei
        for key in dict.keys():
            output = net_connect.send_command('sh cdp nei ' + str(key) + ' detail')
            reg_ip = re.compile(r'(?:IP\saddress\:\s+)(\d+\.\d+\.\d+\.\d+)')
            IP = reg_ip.search(output)
            if IP:
                IP = IP.group(1)
                temp = dict.keys()
                if IP not in dict.keys():
                    dict[IP] = dict[key]
                    del dict[key]

        for key in dict.keys():
            print(dict)
            callfunc(key, dict[key], username, password)
    else:
        #session not created
        pass






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



def single_search(ipaddr, macaddr,username,password):
    input_vals = {'IP': ipaddr, 'mac': normalize_mac(macaddr)}

    # Regexs
    reg_PC = re.compile(r'( Po\d)')  # Group 0: search for Port Channel
    reg_PC_port = re.compile(r'..(\d/)*\d/\d{1,2}')  # Group 0: Port in port channel (or mac address table)
    reg_mac_addr = re.compile(r'....\.....\.....')  # Group 0: Port in port channel (or mac address table)
    reg_CDP_Phone = re.compile(r'Phone')  # Group 0: Check CDP neigh for Phone
    reg_IP_addr = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Group 0: Check for IP

    print("IP Address:{}".format(input_vals['IP']))
    print("MAC Address:{}".format(input_vals['mac']))


    next_ip = input_vals['IP']

    ### START OF LOOOP - loop to the bottom most port that the MAC is found on
    while next_ip is not 0:

        # Switch Parameters
        net_connect = create_connection(next_ip, username, password)
        # zero out next ip. This will be compared to see if there is another switch required to jump into
        current_ip = next_ip
        next_ip = 0

        # SSH Connection
        if net_connect:
            ### ADD ERROR HANDLING FOR FAILED CONNECTION
            print("-------- CONNECTED --------")

            # Show Interface Status
            output = net_connect.send_command('show mac address-table | i ' + input_vals['mac'])
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
                                                                                           current_ip))
                    print("port info: {}".format(port_info))
                else:
                    # look for an IP address in CDP neighbour
                    reg_find = reg_IP_addr.search(output)
                    # if an IP is found, it is a switch (assuming it isn't an AP)
                    if reg_find is not None:
                        print("Mac {} found on port {}".format(macHolder.group(0), port_reg_find.group(0)))
                        next_ip = reg_find.group(0)  # assign the next IP and continue
                    # no CDP info is there, it should be a client port
                    else:
                        # port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                        print("the furthest downstream location is: {} on switch IP:{}".format(port_reg_find.group(0),
                                                                                               current_ip))
                        print("port info: {}".format(port_info))

                #    print ("output = {}".format(output))
                #    print ("find = {}".format(reg_find))
                #    print ("formatted = {}".format(reg_find.group(0)))

                # Close Connection
                net_connect.disconnect()
            else:
                print("Mac address not found.")
    print("-------- COMPLETE --------")


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




def mac_search(ipaddr, macaddr,username,password):

    input_vals = {'IP':ipaddr,'mac': normalize_mac(macaddr)}

    # Regexs
    reg_PC = re.compile(r'( Po\d)') #Group 0: search for Port Channel
    reg_PC_port = re.compile(r'..(\d/)*\d/\d{1,2}') #Group 0: Port in port channel (or mac address table)
    reg_mac_addr = re.compile(r'....\.....\.....') #Group 0: Port in port channel (or mac address table)
    reg_CDP_Phone = re.compile(r'Phone') #Group 0: Check CDP neigh for Phone
    reg_IP_addr = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') #Group 0: Check for IP

    print ("IP Address:{}".format(input_vals['IP']))
    print ("MAC Address:{}".format(input_vals['mac']))


    #IP Verification - Not functional at the moment
    #ping = str(subprocess.run(['ping','-c','1',in_ip_add], stdout=subprocess.DEVNULL))
    #while ('returncode=1' in ping):
    #    print('Host is not Reachable')
    #    in_ip_add = input('Enter the IP/FQDN: ')
    #    ping = str(subprocess.run(['ping','-c','1',in_ip_add], stdout=subprocess.DEVNULL))

    next_ip = input_vals['IP']

    ### START OF LOOOP - loop to the bottom most port that the MAC is found on
    while next_ip is not 0 :
        print ('------- CONNECTING to switch {}-------'.format(next_ip))

        # Switch Parameters
        cisco_sw = {
            'device_type': 'cisco_ios',
            'ip':   next_ip,
            'username': username,
            'password': password,
            'port' : 22,
            'verbose': False,
        }
        #zero out next ip. This will be compared to see if there is another switch required to jump into
        current_ip = next_ip
        next_ip=0

        # SSH Connection
        net_connect = ConnectHandler(**cisco_sw)
        if net_connect:
            ### ADD ERROR HANDLING FOR FAILED CONNECTION
            print ("-------- CONNECTED --------")

            # Show Interface Status
            output = net_connect.send_command('show mac address-table | i '+ input_vals['mac'])
            macHolder = reg_mac_addr.search(output)

            if macHolder is not None:

                #if a port channel then-->
                if "Po" in output:
                    reg_find = reg_PC.search(output)
                    output = net_connect.send_command('show etherchannel summary | include '+ reg_find.group(0))
                port_reg_find = reg_PC_port.search(output)
                #currently the following command gets multiple matches on things like 1/0/1 (11,12,13, etc)
                port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                output = net_connect.send_command("show cdp neigh {} detail".format(port_reg_find.group(0)))
                #check if the cdp neigh information is a phone
                reg_find = reg_CDP_Phone.search(output)
                #if it is a phone....
                if reg_find is not None:
                    print("the furthest downstream location is: {} on switch IP:{}".format(port_reg_find.group(0), current_ip))
                    print("port info: {}".format(port_info))
                else:
                    #look for an IP address in CDP neighbour
                    reg_find = reg_IP_addr.search(output)
                    #if an IP is found, it is a switch (assuming it isn't an AP)
                    if reg_find is not None:
                        print ("Mac {} found on port {}".format(macHolder.group(0),port_reg_find.group(0)))
                        next_ip = reg_find.group(0) # assign the next IP and continue
                    #no CDP info is there, it should be a client port
                    else:
                        #port_info = net_connect.send_command("show int status | i {} ".format(port_reg_find.group(0)))
                        print("the furthest downstream location is: {} on switch IP:{}".format(port_reg_find.group(0), current_ip))
                        print("port info: {}".format(port_info))



            #    print ("output = {}".format(output))
            #    print ("find = {}".format(reg_find))
            #    print ("formatted = {}".format(reg_find.group(0)))

                # Close Connection
                net_connect.disconnect()
            else:
                print("Mac address not found.")
    print ("-------- COMPLETE --------")
    #print ('############################')

#if being run by itself
if __name__ == "__main__":
    #import files to load config and parse CLI
    import config
    import argparse

    config.load_sw_base_conf()
    parser = argparse.ArgumentParser(description='Navigate mac address tables to find a specified MAC.')
    parser.add_argument('startip', metavar='IP',
                        help='The IP to start looking for the mac address at')
    parser.add_argument('macaddr', metavar='MAC',
                        help='The MAC address to search for ')
    args = parser.parse_args()
    mac_search(args.startip, normalize_mac(args.macaddr), config.username, config.password)