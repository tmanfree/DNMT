#!/usr/bin/env python3

from netmiko import ConnectHandler
import random
import re
import socket
import time
from pysnmp.hlapi import *
import netmiko
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
        self.checklog = ""



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

        self.subs.snmp_save_config(ipaddr)

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
    def snmpproc(self, ipaddr,dns_hostname,dns_domain,**kwargs):
        try:
            reg_FQDN = re.compile("([^.]*)\.(.*)")  # Group 0: hostname, Group 1: domain name

            varBinds = self.subs.snmp_get(ipaddr, ObjectType(ObjectIdentity(
                '1.3.6.1.2.1.1.5.0')))
            if (varBinds): # if getting the hostname from snmp was successful
                dns_oid, dns_value = varBinds[0] #grab dns value & oid
                dns_value=str(dns_value) # change dns_value to string rather than DisplayString
                #add error handling here for if there is no domain name {TODO}
                sw_reg_hostname = reg_FQDN.search(dns_value)
                if sw_reg_hostname is None: # HP switches do not have the domain name in The Return
                    sw_hostname = dns_value
                else:
                    sw_hostname = sw_reg_hostname.group(1) #extract the hostname from the FQDN
                #check to see if the hostname and dns are the same
                if dns_hostname.casefold() != sw_hostname.casefold():
                #Send the new hostname if they are different
                    if self.cmdargs.check:
                        self.checklog += "{} hostname is different\n".format(ipaddr)
                    print("hostnames are different\n"
                          "IP:{}\n"
                          "DNS/Manual:{}\n"
                          "Switch    :{}\n".format(ipaddr, dns_hostname, sw_hostname))
                    if not self.cmdargs.check:
                        print("Attempting to update hostname on switch...")
                        # varBinds = self.subs.snmp_get(ipaddr, ObjectType(ObjectIdentity(
                        #     '1.3.6.1.2.1.1.5.0'),dns_hostname.upper()))
                        varBinds = self.subs.snmp_set(ipaddr, ObjectType(ObjectIdentity(
                            '1.3.6.1.2.1.1.5.0'), dns_hostname.upper()))
                        self.subs.snmp_save_config(ipaddr)
                        if (varBinds):#hostname was updated successfully
                            #call itself to confirm it is updated.
                            self.snmpproc(ipaddr, dns_hostname, dns_domain)
                            return True
                    else: # if check flag is indicated
                        return True # return true so that the program doesn't try to login to check again
                else:  #they are the same
                    if self.cmdargs.check and not self.cmdargs.suppress:
                        self.checklog += "{} hostname is the same\n".format(ipaddr)
                    print("hostnames are up to date\n"
                          "IP:{}\n"
                          "DNS/Manual:{}\n"
                          "Switch    :{}\n".format(ipaddr, dns_hostname, sw_hostname))
                    return True
            #if sending was not successful
        except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
            print("SNMP PROC ERROR {}:{}".format(ipaddr, err.args[0]))
        return False



    def loginproc(self, ipaddr,dns_hostname,dns_domain,**kwargs):


        # SSH Connection
        try:
            if 'manual' in self.cmdargs and self.cmdargs.manual:
                manual_credentials = kwargs.get('manualcreds')
                row_titles = kwargs.get('rowtitles')

                if "telnet" in manual_credentials[row_titles.index("type")]:
                    net_connect = self.subs.create_connection_manual(ipaddr, manual_credentials[row_titles.index("type")],
                                                                 manual_credentials[row_titles.index("user")],
                                                                 manual_credentials[row_titles.index("pass")],
                                                                 manual_credentials[row_titles.index("en")],
                                                                 manual_credentials[row_titles.index("port")],
                                                                 "sername", "assword")
                else:
                    net_connect = self.subs.create_connection_custom(ipaddr,
                                                                     manual_credentials[row_titles.index("type")],
                                                                     manual_credentials[row_titles.index("user")],
                                                                     manual_credentials[row_titles.index("pass")],
                                                                     manual_credentials[row_titles.index("en")],
                                                                     manual_credentials[row_titles.index("port")])

            else:
                net_connect = self.subs.create_connection(ipaddr)
            #net_connect = ConnectHandler(**cisco_sw)
            if net_connect:
                ### ADD ERROR HANDLING FOR FAILED CONNECTION
                print("-------- CONNECTED --------")

                # grab hostname
                sw_hostname = net_connect.find_prompt()
                # sw_mode = sw_hostname[-1]
                sw_hostname = sw_hostname.replace(">", "")
                sw_hostname = sw_hostname.replace("#", "")
                # output = net_connect.send_command('show ver | i uptime is')
                # sw_hostname = reg_hostname.search(output)

                if sw_hostname.casefold() != dns_hostname.casefold():
                    if self.cmdargs.check:
                        self.checklog += "{} hostname is different\n".format(ipaddr)
                    print("hostnames are different\n"
                          "IP:{}\n"
                          "DNS   :{}\n"
                          "Switch:{}\n".format(ipaddr, dns_hostname, sw_hostname))
                    if not self.cmdargs.check:
                        self.subs.custom_printer("verbose", "## {} - applying new hostname ##".format(ipaddr.rstrip()))
                        command_str = "hostname " + dns_hostname.upper()
                        if 'manual' in self.cmdargs and self.cmdargs.manual:
                            enable_success = self.subs.vendor_enable(manual_credentials[row_titles.index("type")], net_connect)
                        else:
                            net_connect.enable()
                        output = net_connect.send_config_set([command_str])

                        if 'manual' in self.cmdargs and self.cmdargs.manual:
                            if "telnet" in manual_credentials[row_titles.index("type")]:
                                save_output, new_sw_hostname = self.subs.hp_save_config(net_connect)
                        else:
                            net_connect.save_config()
                        #net_connect.commit()
                        #net_connect.send_command('wr mem')
                        #print (output)
                        new_sw_hostname = new_sw_hostname.strip()
                        new_sw_hostname = new_sw_hostname.replace(">", "")
                        new_sw_hostname = new_sw_hostname.replace("#", "")
                        if new_sw_hostname.casefold() == dns_hostname.casefold():
                            print("SUCCESS, hostnames are up to date\n"
                                  "IP:{}\n"
                                  "DNS   :{}\n"
                                  "Switch:{}\n".format(ipaddr, dns_hostname, sw_hostname))
                        else:
                            print("ERROR, hostnames are not up to date\n"
                                  "IP:{}\n"
                                  "DNS   :{}\n"
                                  "Switch:{}\n".format(ipaddr, dns_hostname, sw_hostname))

                else:
                    if self.cmdargs.check and not self.cmdargs.suppress:
                        self.checklog += "{} hostname is the same\n".format(ipaddr)
                    print("hostnames are up to date\n"
                          "IP:{}\n"
                          "DNS   :{}\n"
                          "Switch:{}\n".format(ipaddr, dns_hostname, sw_hostname))

                    # Close Connection
                net_connect.disconnect()
        except netmiko.ssh_exception.NetMikoAuthenticationException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
        except netmiko.ssh_exception.NetMikoTimeoutException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
        except ValueError as err:
            print(err.args[0])
        except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
            print("NETMIKO ERROR {}:{}".format(ipaddr, err.args[0]))


    #def hostname_update(iplist,username,password,snmp_ro,snmp_rw,check_flag):
    def hostname_update(self,):

        # Regexs
        reg_FQDN = re.compile("([^.]*)\.(.*)")  # Group 0: hostname, Group 1: domain name

        if self.cmdargs.check:
            self.checklog = "SUMMARY of Hostnames:\n"




        file = open(self.cmdargs.iplist, "r")
        #if not self.cmdargs.check:
        if self.cmdargs.peek:
            print("IP,Hostname")
        if 'manual' in self.cmdargs and self.cmdargs.manual:
            row_titles = next(file).split(',')  # grab the first row (the titles) use these to make the standardize switch call dynamic
            row_titles[len(row_titles) - 1] = row_titles[len(row_titles) - 1].rstrip()  # remove the trailing newline
        for ipaddr in file:
            #have a check for gethostbyname or addr)
            self.subs.custom_printer("verbose", "## processing entry - {} ##".format(ipaddr.rstrip()))
            try:
                ipaddr = ipaddr.rstrip().replace(" ","").split(",")

                if len(ipaddr) == 1:
                    dns_fqdn = socket.gethostbyaddr(ipaddr[0])
                    dns_reg_hostname = reg_FQDN.search(dns_fqdn[0])
                    dns_hostname = dns_reg_hostname.group(1)
                    dns_domain = dns_reg_hostname.group(2)

                elif len(ipaddr) == 3:
                    dns_hostname = ipaddr[1]
                    dns_domain = ipaddr[2]
                elif ('manual' in self.cmdargs and self.cmdargs.manual):
                    try:
                        dns_hostname = ipaddr[row_titles.index("host")]
                        dns_domain = ipaddr[row_titles.index("domain")]
                    except IndexError: #called if there is no host entry
                        dns_fqdn = socket.gethostbyaddr(ipaddr[row_titles.index("ip")])
                        dns_reg_hostname = reg_FQDN.search(dns_fqdn[0])
                        dns_hostname = dns_reg_hostname.group(1)
                        dns_domain = dns_reg_hostname.group(2)


                if self.cmdargs.peek:
                    print("{},{}.{}".format(ipaddr[0], dns_hostname, dns_domain))

                #success = snmpproc(ipaddr,dns_hostname,dns_domain,snmp_ro,snmp_rw,check_flag)
                if not self.cmdargs.peek:
                    success = self.snmpproc(ipaddr[0], dns_hostname, dns_domain)


                    if not success:
                        print("SNMP failed, attempting through SSH")
                        if ('manual' in self.cmdargs and self.cmdargs.manual):
                            self.loginproc(ipaddr[0],dns_hostname,dns_domain,manualcreds=ipaddr,rowtitles=row_titles)
                        else:
                            self.loginproc(ipaddr[0], dns_hostname, dns_domain)


            except socket.herror:
                if self.cmdargs.peek:
                    print("{},N/A".format(ipaddr[0]))
                else:
                    if self.cmdargs.check:
                        self.checklog += "{} hostname not in dns\n".format(ipaddr)
                    print("Hostname not found in DNS for IP:{}".format(ipaddr))
            self.subs.custom_printer("verbose", "## Finished processing entry - {} ##".format(ipaddr[0].rstrip()))
        file.close()
        if self.cmdargs.check:
            print("{}".format(self.checklog))
        return

