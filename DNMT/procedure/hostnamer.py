#!/usr/bin/env python3

from netmiko import ConnectHandler
import random
import re
import socket
import time
from pysnmp.hlapi import *
#from procedure import subroutines
### absolute pathing
#from DNMT.procedure import subroutines
from DNMT.procedure.subroutines import SubRoutines
import sys

class HostNamer:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)

    def write_test(self,ipaddr):

        randnum = random.randint(1,100)
        if (self.subs.snmp_set(ipaddr,
                                 ObjectType(ObjectIdentity('CISCO-CONFIG-COPY-MIB', 'ccCopySourceFileType', randnum
                                                           ).addAsn1MibSource('file:///usr/share/snmp',
                                                                              'http://mibs.snmplabs.com/asn1/@mib@'), 4),
                                 ObjectType(ObjectIdentity('CISCO-CONFIG-COPY-MIB', 'ccCopyDestFileType', randnum
                                                           ).addAsn1MibSource('file:///usr/share/snmp',
                                                                              'http://mibs.snmplabs.com/asn1/@mib@'), 3),
                                 ObjectType(ObjectIdentity('CISCO-CONFIG-COPY-MIB', 'ccCopyEntryRowStatus', randnum
                                                           ).addAsn1MibSource('file:///usr/share/snmp',
                                                                              'http://mibs.snmplabs.com/asn1/@mib@'), 4)
                                 )):

            complete = False
            secs = 0

            while not complete and secs < 30:
                varBinds = self.subs.snmp_get(ipaddr, ObjectType(ObjectIdentity(
                    'CISCO-CONFIG-COPY-MIB', 'ccCopyState', randnum).addAsn1MibSource(
                    'file:///usr/share/snmp',
                    'http://mibs.snmplabs.com/asn1/@mib@')))
                if (varBinds):
                    return_oid, return_value = varBinds[0]
                    return_value = str(return_value)  # change value to string rather than DisplayString
                    ### temp printing
                    for varBind in varBinds:
                        print(' = '.join([x.prettyPrint() for x in varBind]))
                    ### temp print end
                    if return_value == "successful":
                        complete = True
                    else:
                        time.sleep(1)
                        secs += 1
            if complete:
                #clear the copy table
                if (self.subs.snmp_set(ipaddr,ObjectType(ObjectIdentity(
                        'CISCO-CONFIG-COPY-MIB', 'ccCopyEntryRowStatus', randnum).addAsn1MibSource(
                        'file:///usr/share/snmp',
                        'http://mibs.snmplabs.com/asn1/@mib@'),6))):
                    print("Job complete")




    def bulk_vlan_change(self,ipaddr,old_vlan,new_vlan):

        #add checking if the vlan exists first, add write mem after change
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in nextCmd(SnmpEngine(),
                                  CommunityData(self.config.ro),
                                  UdpTransportTarget((ipaddr, 161)),
                                  ContextData(),
                                  ObjectType(ObjectIdentity('CISCO-VLAN-MEMBERSHIP-MIB', 'vmVlan').addAsn1MibSource('file:///usr/share/snmp',
                                                                                               'http://mibs.snmplabs.com/asn1/@mib@')),
                                  lexicographicMode=False):
            if errorIndication:
                print(errorIndication)
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            else:  # if getting the hostname from snmp was successful
                grabbed_oid, grabbed_value = varBinds[0]  # grab dns value & oid
                oidvar = grabbed_oid._ObjectIdentity__args[0]._value[grabbed_oid._ObjectIdentity__args[0]._value.__len__()-1]
                if str(grabbed_value) == old_vlan:
                    if (self.subs.snmp_set(ipaddr, ObjectType(ObjectIdentity(
                            'CISCO-VLAN-MEMBERSHIP-MIB', 'vmVlan', oidvar).addAsn1MibSource(
                            'file:///usr/share/snmp',
                            'http://mibs.snmplabs.com/asn1/@mib@'), new_vlan))):
                        print("placeholder vlan ID updated")

        self.write_test(ipaddr)



    # def snmp_test(ipaddr,config,oid):
    #
    #
    #     for (errorIndication,
    #          errorStatus,
    #          errorIndex,
    #          varBinds) in nextCmd(SnmpEngine(),
    #                               CommunityData(config.ro),
    #                               UdpTransportTarget((ipaddr, 161)),
    #                               ContextData(),
    #                               ObjectType(ObjectIdentity('CISCO-VLAN-MEMBERSHIP-MIB', 'vmVlan').addAsn1MibSource('file:///usr/share/snmp',
    #                                                                                            'http://mibs.snmplabs.com/asn1/@mib@')),
    #                               lexicographicMode=False):
    #         if errorIndication:
    #             print(errorIndication)
    #         elif errorStatus:
    #             print('%s at %s' % (errorStatus.prettyPrint(),
    #                                 errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    #         else:  # if getting the hostname from snmp was successful
    #             dns_oid, dns_value = varBinds[0]  # grab dns value & oid
    #             print ("oid:{}\nvalue:{}".format(str(dns_oid),str(dns_value)))
    #
    #
    def snmpproc(self, ipaddr,dns_hostname,dns_domain):
        reg_FQDN = re.compile("([^.]*)\.(.*)")  # Group 0: hostname, Group 1: domain name

        varBinds = self.subs.snmp_get(ipaddr, ObjectType(ObjectIdentity(
            '1.3.6.1.2.1.1.5.0')))
        if (varBinds): # if getting the hostname from snmp was successful
            dns_oid, dns_value = varBinds[0] #grab dns value & oid
            dns_value=str(dns_value) # change dns_value to string rather than DisplayString
            #add error handling here for if there is no domain name {TODO}
            sw_reg_hostname = reg_FQDN.search(dns_value)
            sw_hostname = sw_reg_hostname.group(1) #extract the hostname from the FQDN
            #check to see if the hostname and dns are the same
            if dns_hostname.casefold() != sw_hostname.casefold():
            #Send the new hostname if they are different
                print("hostnames are different\n"
                      "IP:{}\n"
                      "DNS   :{}\n"
                      "Switch:{}\n".format(ipaddr, dns_hostname, sw_hostname))
                if not self.cmdargs.check:
                    print("Attempting to update hostname on switch...")
                    # varBinds = self.subs.snmp_get(ipaddr, ObjectType(ObjectIdentity(
                    #     '1.3.6.1.2.1.1.5.0'),dns_hostname.upper()))
                    varBinds = self.subs.snmp_set(ipaddr, ObjectType(ObjectIdentity(
                        '1.3.6.1.2.1.1.5.0'), dns_hostname.upper()))
                    if (varBinds):#hostname was updated successfully
                        #call itself to confirm it is updated.
                        self.snmpproc(ipaddr, dns_hostname, dns_domain)
                        return True
                else: # if check flag is indicated
                    return True # return true so that the program doesn't try to login to check again
            else:  #they are the same
                print("hostnames are up to date\n"
                      "IP:{}\n"
                      "DNS   :{}\n"
                      "Switch:{}\n".format(ipaddr, dns_hostname, sw_hostname))
                return True
            #if sending was not successful
        return False


    def loginproc(self, ipaddr,dns_hostname,dns_domain):


        print('------- CONNECTING to switch {}-------'.format(ipaddr))

        # SSH Connection
        net_connect = self.subs.create_connection(ipaddr)
        #net_connect = ConnectHandler(**cisco_sw)
        if net_connect:
            ### ADD ERROR HANDLING FOR FAILED CONNECTION
            print("-------- CONNECTED --------")

            # grab hostname
            sw_hostname = net_connect.find_prompt()
            sw_hostname = sw_hostname.replace(">", "")
            sw_hostname = sw_hostname.replace("#", "")
            # output = net_connect.send_command('show ver | i uptime is')
            # sw_hostname = reg_hostname.search(output)

            if sw_hostname.casefold() != dns_hostname.casefold():
                print("hostnames are different\n"
                      "IP:{}\n"
                      "DNS   :{}\n"
                      "Switch:{}\n".format(ipaddr, dns_hostname, sw_hostname))
                if not self.cmdargs.check:
                    command_str = "hostname " + dns_hostname.upper()
                    net_connect.enable()
                    output = net_connect.send_config_set([command_str])
                    #net_connect.save_config()
                    #net_connect.commit()
                    #net_connect.send_command('wr mem')
                    #print (output)

            else:
                print("hostnames are up to date\n"
                      "IP:{}\n"
                      "DNS   :{}\n"
                      "Switch:{}\n".format(ipaddr, dns_hostname, sw_hostname))

                # Close Connection
            net_connect.disconnect()


    #def hostname_update(iplist,username,password,snmp_ro,snmp_rw,check_flag):
    def hostname_update(self,):

        # Regexs
        reg_FQDN = re.compile("([^.]*)\.(.*)")  # Group 0: hostname, Group 1: domain name


        file = open(self.cmdargs.iplist, "r")
        for ipaddr in file:
            #have a check for gethostbyname or addr)
            try:
                ipaddr = ipaddr.rstrip()
                dns_fqdn = socket.gethostbyaddr(ipaddr)
                dns_reg_hostname = reg_FQDN.search(dns_fqdn[0])
                dns_hostname = dns_reg_hostname.group(1)
                dns_domain = dns_reg_hostname.group(2)
                #success = snmpproc(ipaddr,dns_hostname,dns_domain,snmp_ro,snmp_rw,check_flag)
                success = self.snmpproc(ipaddr, dns_hostname, dns_domain)

                if not success:
                    print("SNMP failed, attempting through SSH")
                    self.loginproc(ipaddr,dns_hostname,dns_domain)

            except socket.herror:
                print("Hostname not found in DNS for IP:{}".format(ipaddr))
        file.close()
        return


#
# #if being run by itself
# if __name__ == "__main__":
#     #import files to load config and parse CLI
#     import config
#     import argparse
#
#     config.load_sw_base_conf()
#     parser = argparse.ArgumentParser(description='Check if the hostnames of a list of IPs are identical to DNS.')
#     parser.add_argument('iplist', metavar='FILENAME',
#                         help='The list that contains the ip addresses to check')
#     parser.add_argument('-c', '--check', help="Compare hostname, do not change", action="store_true")
#     cmdargs = parser.parse_args()
#
#     MainFunc = HostNamer(cmdargs,config)
#     MainFunc.hostname_update(cmdargs.check)



