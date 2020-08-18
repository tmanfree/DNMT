#!/usr/bin/env python3

#TODO Add Try/Except loops for proper error handling
#TODO flash verification skipping for 4500 & 2950T models
#Warning - Does not work on 4500 or 2950 T models

import re
import sys
import subprocess,platform,os,time,datetime
import getpass
import difflib
import pickle
import socket
import dns.resolver
import dns.zone

#for the port labelling
import imaplib
import email
import ast


#3rd party imports
import netmiko
from pathos.multiprocessing import ProcessingPool as Pool

#local subroutine import
from DNMT.procedure.subroutines import SubRoutines



class Tools:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        #self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
        #                                   datetime.date.today().strftime('%Y%m%d'))

    def TDR_Test(self,net_connect,interface):
        net_connect.enable()
        print("performing diagnostic on {}".format(interface))
        result = net_connect.send_command('test cable-diagno tdr interface {}'.format(interface))
        print("waiting for 15 seconds")
        time.sleep(15)
        test_result = net_connect.send_command('show cable-diagnostics tdr int {}'.format(interface))
        print("Results are:\n{}".format(test_result))
        #net_connect.disable() #incorrect syntax

        return



    def Ap_Poke(self):
        #cmdargs.interface
        #cmdargs.ipaddr


        #format interface string:
        self.cmdargs.interface = re.sub('[a-zA-Z]', '', self.cmdargs.interface)

        if self.subs.ping_check(self.cmdargs.ipaddr):
            self.subs.verbose_printer(print(
                "{} Reachable, Now performing AP Poke Operation on {}".format(self.cmdargs.ipaddr,
                                                                              self.cmdargs.interface)))
            if self.cmdargs.login:
                self.config.username = input("Input user name to login to switch:")
                self.config.password = getpass.getpass("Input password to login to switch:")
                self.config.enable_pw = getpass.getpass("Input enable password for switch:")

            try:
                net_connect = self.subs.create_connection(self.cmdargs.ipaddr)

                if net_connect:
                    swcheck_dict = {"ip": self.cmdargs.ipaddr, "interface": self.cmdargs.interface}
                    net_connect.send_command('term shell 0')
                    swcheck_dict["sh_int_status"] = net_connect.send_command(
                        'show int status | include {} .'.format(swcheck_dict["interface"]))
                    #create a variable to grab speed (assuming just a number is passed (1/0/11 for example)
                    # if re.search('[a-zA-Z]', self.cmdargs.interface):
                    #     swcheck_dict["local_int"] = self.cmdargs.interface
                    # else:
                    swcheck_dict["local_int"] = self.subs.regex_parser_var0(r'^(\S+)',swcheck_dict["sh_int_status"])

                    swcheck_dict["sh_int"] = net_connect.send_command(
                        'show int {} | include {} .'.format(swcheck_dict["local_int"], swcheck_dict["interface"]))
                    swcheck_dict["sh_mac"] = net_connect.send_command(
                        'show mac address int {}'.format(swcheck_dict["local_int"]))
                    swcheck_dict["mac_stat"] = \
                        re.findall(r'({}+)'.format(swcheck_dict["interface"]), swcheck_dict["sh_mac"], re.MULTILINE)
                    swcheck_dict["sh_cdp"] = net_connect.send_command(
                        'show cdp neigh {}'.format(swcheck_dict["local_int"]))
                    swcheck_dict["cdp_stat"] = \
                        re.findall(r'entries displayed : (\S+)', swcheck_dict["sh_cdp"], re.MULTILINE)
                    swcheck_dict["sh_power"] = net_connect.send_command(
                        'show power inline | include {} .'.format(swcheck_dict["interface"]))
                    swcheck_dict["power_stat"] = self.subs.regex_parser_var0(r'^(?:\S+\s+\S+\s+\S+\s+\S+\s+)(\S+)',
                                                                             swcheck_dict["sh_power"])
                    swcheck_dict["int_stat"] = self.subs.regex_parser_var0(r'(?:line protocol is \S+ \()(\S+)\)',
                                                                           swcheck_dict["sh_int"])
                    swcheck_dict["power_stat"] = self.subs.regex_parser_var0(r'^(?:\S+\s+\S+\s+\S+\s+\S+\s+)(\S+)', swcheck_dict["sh_power"])
                    swcheck_dict["int_stat"] = self.subs.regex_parser_var0(r'(?:line protocol is )(\S+)',swcheck_dict["sh_int"] )


                    self.subs.verbose_printer(
                        "Switch:{}\nInterface:{}\nInt Status:{}\nPower Status:{}\n# of MACs:{}".format(
                            swcheck_dict["ip"], swcheck_dict["local_int"], swcheck_dict["int_stat"],
                            swcheck_dict["power_stat"], len(swcheck_dict["mac_stat"])))

                    # Currently will only work if:
                    # -The port is down (AP may be locked up)
                    # -The port is up with an AP (catches some odd APs behaviour, used on 100M connections)
                    # -The port is up with Ieee and 0 Mac Addresses (AP is locked up)
                    if (swcheck_dict["int_stat"] == "notconnect") or (swcheck_dict["int_stat"] == "connected" and (
                            ("AIR" in swcheck_dict["power_stat"]) or (
                            "Ieee" in swcheck_dict["power_stat"] and len(swcheck_dict["mac_stat"]) == 0))):


                        # #TODO Add some logic to reload APs if not fincioning correctly
                        # if "AIR" in swcheck_dict['sh_cdp']:
                        #     response = input("Port appears to have a live AP, confirm action of toggling port on/off ('yes'):")
                        #     if not response == 'yes':
                        #         self.subs.verbose_printer('Did not proceed with change.')
                        #         sys.exit(1)

                        print("Change appears safe*") # change mac addresses to be 0,
                        if not self.cmdargs.skip:
                            if self.cmdargs.tdr: #Run a TDR test before if flag is set
                                self.TDR_Test(net_connect,swcheck_dict['local_int'])
                            response = input("Confirm action of toggling port on/off ('yes'):")
                            if not response == 'yes':
                                self.subs.verbose_printer('Did not proceed with change.')
                                sys.exit(1)



                        self.subs.snmp_reset_interface(self.cmdargs.ipaddr,
                            self.subs.snmp_get_interface_id(self.cmdargs.ipaddr,
                                                                     swcheck_dict["local_int"]))
                        # net_connect.enable()
                        # config_command = ["interface " + swcheck_dict["local_int"], "shutdown"]
                        # shutdown_output = net_connect.send_config_set(config_command)
                        # self.subs.verbose_printer('Port Shutdown, waiting 5 seconds.')
                        # time.sleep(5)
                        # config_command = ["interface " + swcheck_dict["local_int"], "no shutdown"]
                        # shutdown_output = net_connect.send_config_set(config_command)
                        # self.subs.verbose_printer('Port Enabled.')

                    else:
                        print("Change may be unsafe, exiting.")
                       # net_connect.send_command('int {}'.format(swcheck_dict["local_int"]))
                       # net_connect.send_command('shutdown')
                    net_connect.disconnect()
            # netmiko connection error handling
            except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
                sys.exit(1)
            except netmiko.ssh_exception.NetMikoTimeoutException as err:
                self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
                sys.exit(1)
            except ValueError as err:
                print(err.args[0])
                sys.exit(1)
            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                print("NETMIKO ERROR {}:{}".format(self.cmdargs.ipaddr, err.args[0]))
                sys.exit(1)
#
#

    def Change_Port_Vlan(self):
      #TODO update to have batch file act on csv with format <IP,interface,vlan,desc> desc optional?
      # have csv in format of <KEY=VAL,KEY=VAL,KEY=VAL, need IP,interface as first two EX <A.A.A.A,Gi1/0/1,DESC=blah>
        vendor = self.subs.snmp_get_vendor_string(self.cmdargs.ipaddr)
        vlanList = self.subs.snmp_get_vlan_database(self.cmdargs.ipaddr,vendor)


        for vlan in vlanList:
            print("Vlan ID:{} Vlan Name:{}".format(vlan["ID"],vlan["Name"].decode("utf-8")))



        # Find the ID of the requested interface
        intId = self.subs.snmp_get_interface_id(self.cmdargs.ipaddr, self.cmdargs.interface)

        fullInterface = self.subs.snmp_get_full_interface(self.cmdargs.ipaddr, intId)
        intDescription = self.subs.snmp_get_interface_description(self.cmdargs.ipaddr, intId)
        currentVlan = self.subs.snmp_get_interface_vlan(self.cmdargs.ipaddr, intId,vendor)

        #TEST
        self.subs.snmp_set_interface_vlan(self.cmdargs.ipaddr, intId, 2101,int(currentVlan), vendor)


        #enter vlan id to change to
        bLoop = True  # TODO make this more efficient
        while (bLoop):
            print("Interface {} Description:{}".format(fullInterface,intDescription))
            vlanResponse = input("Current Vlan is {} Enter VLAN ID to change to:".format(currentVlan ))
            if any(d['ID'] == int(vlanResponse) for d in vlanList):
                bLoop = False
            else:
                print("Please enter an existing Vlan ID")


        response = input("Do you want to change vlan on port {} from {} to {}?\n"
                         "enter (yes) to proceed:".format(self.cmdargs.interface,currentVlan,vlanResponse))
        if not response == 'yes':
            self.subs.verbose_printer('Did not proceed with change.')
            sys.exit(1)

        #set new vlan
        self.subs.snmp_set_interface_vlan(self.cmdargs.ipaddr, intId, int(vlanResponse), int(currentVlan), vendor)

        #check what vlan is now
        newVlan = self.subs.snmp_get_interface_vlan(self.cmdargs.ipaddr, intId, vendor)

        if int(newVlan) == int(vlanResponse): #
            print("Vlan updated to Vlan {}".format(newVlan))
        else:
            print("vlan not updated, Vlan is still {}".format(newVlan))

        response = input("Do you want to change description on port {} from {}?\n"
                         "enter (yes) to proceed:".format(self.cmdargs.interface, intDescription))
        if not response == 'yes':
            self.subs.verbose_printer('No new Description.')
            sys.exit(1)
        response = input("Enter new description:")
        self.subs.snmp_set_interface_description(self.cmdargs.ipaddr,intId,response)
        newDescription = self.subs.snmp_get_interface_description(self.cmdargs.ipaddr, intId)

        if newDescription == response: #
            print("Description updated to \"{}\"".format(response))
        else:
            print("Description not updated, still \"{}\"".format(newDescription))


    def diggle(self):
        switchlisting = None
        try:
            # Grab the name server first
            soa_answer = dns.resolver.query(self.cmdargs.domain, 'SOA')
            master_answer = dns.resolver.query(soa_answer[0].mname, 'A')
            # could skip previous 2 lines by presetting Name server address
            z = dns.zone.from_xfr(dns.query.xfr(master_answer[0].address, self.cmdargs.domain))
            names = z.nodes.keys()
            matchcounter = 0

            if 'advanced' in self.cmdargs and self.cmdargs.advanced:
                switchlisting = "Hostname , IP , Vendor\n"
            else:
                switchlisting = "Hostname , IP\n"
            for n in names:
                if re.match(self.cmdargs.hoststring, str(n),flags=re.IGNORECASE): #Case insensitive for simplicity
                    matchcounter += 1
                    FQDN = str(n)+"."+self.cmdargs.domain
                    IP = socket.gethostbyname(FQDN)

                    if 'advanced' in self.cmdargs and self.cmdargs.advanced:
                        vendor = self.subs.snmp_get_vendor_string(IP)
                        switchlisting += "{} , {} , {}\n".format(FQDN, IP, vendor)
                    else:
                        switchlisting += "{} , {}\n".format(FQDN,IP)
        except socket.error as e:
            print('Failed to perform zone transfer:', e)
        except dns.exception.FormError as e:
            print('Failed to perform zone transfer:', e)
        except Exception as err:
            print(err)
        if switchlisting is not None:
            print("{}\n Job complete, {} matches found".format(switchlisting,matchcounter))
        else:
            print(" Job complete, NO matches found")

    def Port_Label_Check(self):
        # self.read_email_from_gmail()
        try:
            #login and grab mail from
            mailconnection = imaplib.IMAP4_SSL('imap.gmail.com')
            mailconnection.login(self.config.port_label_email, self.config.port_label_pw)
            mailconnection.select('PortLabels')

            # result, data = mail.search(None, 'ALL')
            # mailconnection.store(b'1', '-FLAGS', '(\\Seen)')
            # mailconnection.uid('STORE', b'1', '+FLAGS', '\SEEN')
            result, data = mailconnection.search(None, 'UNSEEN')
            mail_ids = data[0]

            id_list = mail_ids.split()
            if len(id_list) > 0:
                for msg_index in id_list:
                    int_msg_index = int(msg_index)    # need str(i)
                    result, data = mailconnection.fetch(str(int_msg_index), '(RFC822)') #sets read
                    mailconnection.store(msg_index, '-FLAGS', '(\\Seen)')

                    for response_part in data:
                        if isinstance(response_part, tuple):
                            # from_bytes, not from_string
                            msg = email.message_from_bytes(response_part[1])
                            email_subject = msg['subject']
                            # email_from = msg['from']
                            if (email_subject == '<PORTLABELS> New Port Labels'):
                                email_body = msg.get_payload(decode=True)
                                dict_str = email_body.decode("UTF-8")
                                label_dict = ast.literal_eval(dict_str)
                                if (self.Apply_Port_Labels(label_dict)):
                                    print("Labels applied correctly, message index:{}".format(str(int_msg_index)))
                                    mailconnection.store(msg_index, '+FLAGS', '(\\Seen)')
                                else:
                                    print("ERROR: Labels did not apply correctly, message index:{}".format(
                                        str(int_msg_index)))
                                    mailconnection.store(msg_index, '-FLAGS', '(\\Seen)')

                                # print('From : ' + email_from + '\n')
                                # print('Subject : ' + email_subject + '\n')
                            else:
                                print("ERROR: incorrect message subject, message index:{}, subject:{}".format(
                                    str(int_msg_index),email_subject))
        except Exception as e:
            print("Email processing failure:{}".format(e))

    def Apply_Port_Labels(self,full_label_dict,):
        bSuccess = True
        for switch_dict in full_label_dict['switches']:
            try:
                net_connect = self.subs.create_connection(switch_dict['IP'])
                if net_connect:
                    net_connect.enable()  # move this out of the if/else statements
                    net_connect.send_command('term shell 0')
                    for label in switch_dict['Labels']:
                        if not self.cmdargs.batch:
                            result = net_connect.send_command('show run {}'.format(label['port']))
                            if re.search('Invalid input detected', result) is not None:
                                print("\nERROR grabbing port info of {} on {}, skipping\n".format(label['port'],switch_dict['IP']))
                                bSuccess = False
                            else:
                                response = input(
                                    "Current Config of {}:\n{}\n !!!!  Apply new port label of \"{}\"? (type 'yes' to continue'):".format(
                                        label['port'], result, label['desc']))
                                if not response == 'yes':
                                    print("\nDid not proceed with changing {} on {}, skipping\n".format(label['port'],switch_dict['IP']))
                                    bSuccess = False
                                else:
                                    result = net_connect.send_config_set([label['port'],label['desc']])
                                    if re.search('Invalid input detected', result) is not None:
                                        print("\nERROR updating port info of {} on {}\n".format(label['port'],
                                                                                                      switch_dict[
                                                                                                          'IP']))
                                        bSuccess = False
                        else: #if in batch mode
                            result = net_connect.send_config_set([label['port'],label['desc']])
                            if re.search('Invalid input detected', result) is not None:
                                print("\nERROR updating port info of {} on {}, continuing\n".format(label['port'],
                                                                                              switch_dict[
                                                                                                  'IP']))
                                bSuccess = False
                            #<TODO> add verification of result that there were no issues, search for %?

                    result += net_connect.save_config()
                    if re.search('Invalid input detected', result) is not None:
                        print("\nError saving config on {}\n".format(switch_dict['IP']))
                        bSuccess = False
                    net_connect.disconnect()
            except Exception as e:
                print("\nConnection/label application failure:{}\n".format(e))
                bSuccess = False
        return bSuccess
