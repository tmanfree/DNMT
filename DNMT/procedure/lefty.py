#!/usr/bin/env python3

from netmiko import ConnectHandler
import re
import sys





#Howdy Neighbour!

#Recommended usage Lefty 10.0.0.1 1ef6

def normalize_mac( address):
    tmp3 = address.lower().translate({ord(":"): "", ord("-"): "", ord(" "): ""})

    if len(tmp3) % 4 == 0:
        return '.'.join(a + b + c + d for a, b, c, d in
                    zip(tmp3[::4], tmp3[1::4], tmp3[2::4], tmp3[3::4]))  # insert a period every four chars
    else:
        if len(tmp3) < 4:
            return tmp3
        else:
            print("Please enter a mac address in a group of 4")
            sys.exit()


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
