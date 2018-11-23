#!/usr/bin/env python3

from netmiko import ConnectHandler
import re
import socket
from pysnmp.hlapi import *

import sys


def snmpproc(ipaddr,dns_hostname,dns_domain,snmp_ro, snmp_rw):
    reg_FQDN = re.compile("([^.]*)\.(.*)")  # Group 0: hostname, Group 1: domain name


####TEST
    #get hostname from switch
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(snmp_ro),
               UdpTransportTarget((ipaddr, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')))
    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        dns_oid, dns_value = varBinds[0]
        dns_value=str(dns_value)
        sw_reg_hostname = reg_FQDN.search(dns_value)
        sw_hostname = sw_reg_hostname.group(1)
        #check to see if the hostname and dns are the same
        if dns_hostname.casefold() != sw_hostname.casefold():
        #Send the new
            errorIndication, errorStatus, errorIndex, varBinds = next(
                setCmd(SnmpEngine(),
                       CommunityData(snmp_rw),
                       UdpTransportTarget((ipaddr, 161)),
                       ContextData(),
                       ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'), dns_hostname))
            )

            if errorIndication:
                print(errorIndication)
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            else:
                #return successful
                return True
        else:
            #they are the same
            print("hostnames are already up to date\n"
                  "DNS:{}\n"
                  "Switch:{}\n".format(dns_hostname, sw_hostname))
            return True
        #if sending was not successful
    return False




def loginproc(ipaddr,dns_hostname,dns_domain,username,password):


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

    # SSH Connection
    net_connect = ConnectHandler(**cisco_sw)
    if net_connect:
        ### ADD ERROR HANDLING FOR FAILED CONNECTION
        print("-------- CONNECTED --------")

        # grab hostname
        sw_hostname = net_connect.find_prompt()
        sw_hostname = sw_hostname.replace(">", "")
        sw_hostname = sw_hostname.replace("#", "")
        # output = net_connect.send_command('show ver | i uptime is')
        # sw_hostname = reg_hostname.search(output)

        if sw_hostname.casefold() == dns_hostname.casefold():
            print("hostnames are already up to date\n"
                  "DNS:{}\n"
                  "Switch:{}\n".format(dns_hostname,sw_hostname))
        else:
            print("hostnames are different\n"
                  "DNS:{}\n"
                  "Switch:{}\n"
                  "updating switch to dns name".format(dns_hostname,sw_hostname))

            # Close Connection
        net_connect.disconnect()


def hostname_update(iplist,username,password,snmp_ro,snmp_rw):

    # Regexs
    reg_FQDN = re.compile("([^.]*)\.(.*)")  # Group 0: hostname, Group 1: domain name


    file = open(iplist, "r")
    for ipaddr in file:
        #have a check for gethostbyname or addr)
        try:
            ipaddr = ipaddr.rstrip()
            dns_fqdn = socket.gethostbyaddr(ipaddr)
            dns_reg_hostname = reg_FQDN.search(dns_fqdn[0])
            dns_hostname = dns_reg_hostname.group(1)
            dns_domain = dns_reg_hostname.group(2)
            success = snmpproc(ipaddr,dns_hostname,dns_domain,snmp_ro,snmp_rw)

            if success:
                print("Hostname successfully updated")
            else:
                print("SNMP failed, attempting through SSH")
                loginproc(ipaddr,dns_hostname,dns_domain,username,password)
#            print("The hostname of {} is {}".format(ipaddr, dns_fqdn[0]))
#            print("The hostname is:{} and the domain name is:{}".format(dns_hostname,dns_domain))

        except socket.herror:
            print("Hostname not found in DNS for IP:{}".format(ipaddr))
    file.close()



    print ("-------- COMPLETE --------")
    #print ('############################')

#if being run by itself
if __name__ == "__main__":
    #import files to load config and parse CLI
    import config
    import argparse

    config.load_sw_base_conf()
    parser = argparse.ArgumentParser(description='Check if the hostnames of a list of IPs are identical to DNS.')
    parser.add_argument('iplist', metavar='FILENAME',
                        help='The list that contains the ip addresses to check')
    args = parser.parse_args()
    hostname_update(args.iplist, config.username, config.password)
