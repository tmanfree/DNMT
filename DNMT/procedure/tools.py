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
import smtplib
from email import encoders

#3rd party imports
import netmiko
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathos.multiprocessing import ProcessingPool as Pool

#local subroutine import
from DNMT.procedure.subroutines import SubRoutines

#for standardization configparsing
import configparser



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



    def ap_poke(self):
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

    def change_port_vlan(self):
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

    def port_label_check(self):
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
                            email_from = msg['from']
                            if (email_subject == '<PORTLABELS> New Port Labels'):
                                self.log_array.append("Email processing beginning\n")
                                email_body = msg.get_payload(decode=True)
                                dict_str = email_body.decode("UTF-8")
                                label_dict = ast.literal_eval(dict_str) #WILL BALK AT MULTI LINK DESCRIPTIONS
                                if (self.Apply_Port_Labels(label_dict)):
                                    self.Print_And_Log("Labels applied correctly, message index:{}".format(str(int_msg_index)))
                                    mailconnection.store(msg_index, '+FLAGS', '(\\Seen)')
                                else:
                                    self.Print_And_Log("ERROR: Labels did not apply correctly, message index:{}".format(
                                        str(int_msg_index)))
                                    mailconnection.store(msg_index, '-FLAGS', '(\\Seen)')

                            else:
                               self.Print_And_Log("ERROR: incorrect message subject, message index:{}, subject:{}".format(
                                    str(int_msg_index),email_subject))
                            if self.cmdargs.notify:
                                self.Email_Now(email_from,email_body)
        except Exception as e:
            print("Email processing failure:{}".format(e))



    def Print_And_Log(self,to_print):
        self.subs.verbose_printer(to_print)
        self.log_array[0] += (to_print + "\n")

    def Apply_Port_Labels(self,full_label_dict,):
        #TODO list previous description and new description, to show the change
        #TODO add processing for Vlans
        #TODO make a list of the ports to change and then change them all at the same time (same command_list)
        #   to send to netmiko to improve processing time, rather than jumping in and out of the config for each one

        bSuccess = True
        for switch_dict in full_label_dict['switches']:
            try:
                net_connect = self.subs.create_connection(switch_dict['IP'])
                if net_connect:
                    net_connect.enable()  # move this out of the if/else statements
                    net_connect.send_command('term shell 0')
                    for label in switch_dict['Labels']:
                        current_config = net_connect.send_command('show run {}'.format(label['port']))
                        current_descr = self.subs.regex_parser_var0("description (.*)",current_config)
                        if re.search('Invalid input detected', current_config) is not None:
                            self.Print_And_Log(
                                "\nERROR grabbing port info of {} on {}, skipping\n".format(label['port'],
                                                                                            switch_dict['IP']))
                            bSuccess = False
                        else:
                            if not self.cmdargs.batch:
                                response = input(
                                    "Current Config of {}:\n{}\n !!!!  Apply new port label of \"{}\"? (type 'yes' to continue'):".format(
                                        label['port'], current_config, label['desc']))
                                if not response == 'yes':
                                    self.Print_And_Log("\nDid not proceed with changing {} on {}, skipping\n".format(label['port'],switch_dict['IP']))
                                    bSuccess = False
                                else:
                                    bSuccess = self.Apply_Description(net_connect,label,switch_dict['IP'],current_descr,bSuccess)
                            else: #if in batch mode
                                bSuccess = self.Apply_Description(net_connect,label,switch_dict['IP'],current_descr,bSuccess)
                    result = net_connect.save_config()
                    if re.search('Invalid input detected', result) is not None:
                        self.Print_And_Log("\nError saving config on {}\n".format(switch_dict['IP']))
                        bSuccess = False
                    else:
                        self.Print_And_Log("\nSuccess saving config on {}\n".format(switch_dict['IP']))
                    net_connect.disconnect()
            except Exception as e:
                self.Print_And_Log("\nConnection/label application failure:{}\n".format(e))
                bSuccess = False
        return bSuccess

    def Apply_Description(self,net_connect,label,ipaddr,current_descr,bSuccess):
        result = net_connect.send_config_set([label['port'], label['desc']])
        if re.search('Invalid input detected', result) is not None:
            self.Print_And_Log("\nERROR updating port info of {} on {}\n".format(label['port'],
                                                                                 ipaddr))
            bSuccess = False
        else:
            self.Print_And_Log(
                "\nSuccessfully updated port info of {} on {}\n Old:{} New:{}\n".format(label['port'],
                                                                                        ipaddr,
                                                                                        current_descr, label['desc']))
        return bSuccess

    def Email_Now(self,to_email,original_text):
        try:
            self.subs.verbose_printer("##### Emailing now #####")

            temp_from = "admin@localhost"

            # Create the message
            themsg = MIMEMultipart()
            themsg["From"] = temp_from
            themsg["Subject"] = "response from Port Labelling - {}".format(datetime.date.today().strftime('%Y-%m-%d'))
            themsg["To"] = to_email



            # themsg.preamble = 'I am not using a MIME-aware mail reader.\n'
            # msg = MIMEBase('application', 'zip')
            # msg.set_payload(zf.read())
            # encoders.encode_base64(msg)
            # msg.add_header('Content-Disposition', 'attachment',
            #                filename=status_filename + '.zip')
            #
            #
            # themsg.attach(msg)

            #create the body of the email
            body = self.log_array[0] + "\n"
            body += "\n ------------------------------------\n ORIGINAL MSG BELOW\n{}".format(original_text)+"\n"


            themsg.attach(MIMEText(body, 'plain'))

            themsg = themsg.as_string()

            # send the message
            smtp = smtplib.SMTP()
            smtp.connect()
            smtp.sendmail(temp_from, to_email, themsg)
            smtp.close()

        except smtplib.SMTPException as err:
            print("Failed to send Email:{}".format(err))
        except Exception as err:
            print(err)

    def standardize_begin(self):
        if 'apply' in self.cmdargs and self.cmdargs.apply:
            print("Beginning Apply Standards Operation")
        else:
            print("Beginning Check Standards Operation")
            # File will have mandatory first row with at least these fields:  ip, type, user, pass, en, port
        file = open(self.cmdargs.ipfile, "r")
        summary_list = []

        if 'manual' in self.cmdargs and self.cmdargs.manual:
            row_titles = next(file).split(',') #grab the first row (the titles) use these to make the standardize switch call dynamic
            row_titles[len(row_titles)-1] = row_titles[len(row_titles)-1].rstrip() #remove the trailing newline

        for ip in file:
            if ('manual' in self.cmdargs and self.cmdargs.manual and len(row_titles) == 6): #{IP][Vendor][UN][PW][EN][PORT.split]
                ip_entry = ip.split(',')
                if (len(ip_entry) == len(row_titles)):
                    ip_entry[len(ip_entry)-1] = ip_entry[len(ip_entry)-1].rstrip()
                    summary_list.append(self.Standardize_Switch(ip_entry[row_titles.index("ip")], ip_entry[row_titles.index("type")],
                                            ip_entry[row_titles.index("user")], ip_entry[row_titles.index("pass")],
                                            ip_entry[row_titles.index("en")], ip_entry[row_titles.index("port")]))
            elif 'manual' in self.cmdargs and not self.cmdargs.manual:
                try:
                    vendor = self.subs.snmp_get_vendor_string(ip.rstrip())
                    if vendor =="Cisco":
                        device_type = "cisco_ios"
                    elif vendor =="HP":
                        device_type="hp_procurve"
                    else:
                        device_type="generic_termserver"
                    summary_list.append(self.Standardize_Switch(ip.rstrip(),device_type,self.config.username, self.config.password,self.config.enable_pw,22))
                except Exception as err:
                    print(err)
        file.close()
        print("\nSUMMARY:")
        for entry in summary_list:
            print(entry)

    def Standardize_Switch(self,ipaddr,vendor,username,password,enable_pw,port):
        print_summary = ""
        if self.subs.ping_check(ipaddr):
            try:
                if "hp_procurve_telnet" in vendor:
                    net_connect = self.subs.create_connection_manual(ipaddr, vendor, username, password, enable_pw,
                                                                     port, "sername", "assword")
                else:
                    net_connect = self.subs.create_connection_custom(ipaddr, vendor, username, password, enable_pw, port)
                if 'manual' in self.cmdargs and self.cmdargs.manual:
                    enable_success =self.subs.vendor_enable_manual(vendor,net_connect,username,password,enable_pw)
                else:
                    enable_success =  self.subs.vendor_enable(vendor,net_connect)
                if enable_success:
                    if "hp_procurve" in vendor: #temporary fix for
                        net_connect.send_command("term length 1000")
                    sh_run = net_connect.send_command("show run") # add a check for hp and term length 0?
                    # print(sh_run)
                    #TODO seperate the commandlist into headings like auth=
                    #   then have seperate check/apply fields for some that can have hashed values

                    # commandlist = self.gather_standard_commands(vendor,"tacacsshow")
                    foundnum,missingnum,appliednum,errornum = self.gather_standard_commands(ipaddr,vendor,sh_run,net_connect)

                    self.subs.verbose_printer("{} - {} CMDs exist {} CMDs missing {} CMDs applied {} CMDs Errors".format(ipaddr,foundnum,missingnum,appliednum,errornum))
                    return "{} - {} CMDs exist {} CMDs missing {} CMDs applied {} CMDs Errors".format(ipaddr,foundnum,missingnum,appliednum,errornum)
                else:
                    self.subs.verbose_printer("###{}### ERROR Unable to enable".format(ipaddr))
                    return "{} - Unable to Enable".format(ipaddr)
                net_connect.disconnect()
            except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                self.subs.verbose_printer(err.args[0], "###{}### ERROR Netmiko Authentication Failure ".format(ipaddr))
                return "{} - {}".format(ipaddr,err.args[0])
            except netmiko.ssh_exception.NetMikoTimeoutException as err:
                self.subs.verbose_printer(err.args[0], "###{}### ERROR Netmiko Timeout Failure".format(ipaddr))
                return "{} - {}".format(ipaddr,err.args[0])
            except netmiko.ssh_exception.SSHException as err:
                if (err.args[0] == "Incompatible version (1.5 instead of 2.0)"):
                    self.subs.verbose_printer(err.args[0], "###{}### ERROR Netmiko incompatible version".format(ipaddr))
                    result2 = self.Standardize_Switch(ipaddr, "{}_telnet".format(vendor), username, password, enable_pw, 23)
                    return "{} - {}\n{}".format(ipaddr, err.args[0], result2)
                else:
                    self.subs.verbose_printer(err.args[0], "###{}### ERROR Netmiko SSH Exception".format(ipaddr))
                    return "{} - {}".format(ipaddr, err.args[0])
            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                self.subs.verbose_printer("###{}### ERROR NETMIKO:{}".format(ipaddr, err.args[0]))
                return "{} - {}".format(ipaddr, err.args[0])

        else:
            self.subs.verbose_printer("####{}### ERROR Unable to ping ".format(ipaddr))
            return "{} - No Ping Response".format(ipaddr)


    def gather_standard_commands(self,ipaddr,vendor,sh_run, net_connect):
        config = configparser.ConfigParser()

        #Check wehere to grab the config for
        if 'cmdfile' in self.cmdargs and self.cmdargs.cmdfile is not None:
            config.read(self.cmdargs.cmdfile)
        else:
            config.read(os.path.abspath(os.path.join(os.sep, 'usr', 'lib', 'capt', 'standard.conf')))

        #set the heading to grab from the custom file
        if vendor in ["Cisco", "cisco_ios", "cisco_ios_telnet"]:
            Vendor_Heading = "CISCO"
        elif vendor in ["HP", "hp_procurve", "hp_procurve_telnet"]:
            Vendor_Heading = "HP"
        else:
            Vendor_Heading = "UNKNOWN"

        foundnum = 0
        missingnum = 0
        appliednum=0
        errornum=0

        for Heading in (MainHeading for MainHeading in config if Vendor_Heading in MainHeading ):
            if "BASE" in Heading or "SHOW" in Heading:
                for Category in config[Heading]:
                    command_list = config[Heading][Category].splitlines()
                    if len(command_list) > 1: #for multiline commands
                        try:
                            for command in command_list:
                                if self.check_config_for_command(command, sh_run):
                                    self.subs.verbose_printer("###{}### FOUND: {} ".format(ipaddr, command))
                                    foundnum += 1
                                else:
                                    print("###{}### MISSING: {} ".format(ipaddr, command))
                                    missingnum += 1
                                    if "apply" in self.cmdargs and self.cmdargs.apply:
                                        if "solo" not in Category:  # exit out and apply all if dependent commands
                                            raise ValueError
                                        result = net_connect.send_config_set(command)
                                        if self.subs.print_config_results(ipaddr,result,command):
                                            appliednum +=1
                                        else:
                                            errornum += 1
                        except ValueError:  # break out of that for loop if one of the commands are missing and you have apply set
                            if "BASE" in Heading:
                                send_command_set = config[Heading][
                                    Category].splitlines()  # if missing any of the values for the entry, apply them all
                            elif "SHOW" in Heading:
                                send_command_set = config["{} APPLY".format(Vendor_Heading)][Category].split(',')
                            result = net_connect.send_config_set(send_command_set)
                            if self.subs.print_config_results(ipaddr, result, send_command_set):
                                appliednum += 1
                            else:
                                errornum += 1

                    elif len(command_list) == 1: # for commands with a single entry
                        if self.check_config_for_command(command_list[0],sh_run):
                            self.subs.verbose_printer("###{}### FOUND: {} ".format(ipaddr, command_list[0]))
                            foundnum += 1
                        else:
                            print("###{}### MISSING: {} ".format(ipaddr, command_list[0]))
                            missingnum += 1
                            if 'apply' in self.cmdargs and self.cmdargs.apply:
                                if "BASE" in Heading:
                                    send_command_set = command_list[0]  # if missing any of the values for the entry, apply them all
                                elif "SHOW" in Heading:
                                    send_command_set =config["{} APPLY".format(Vendor_Heading)][Category].split(',')
                                result = net_connect.send_config_set(send_command_set)
                                if self.subs.print_config_results(ipaddr, result, send_command_set):
                                        appliednum += 1
                                else:
                                    errornum += 1
        if "apply" in self.cmdargs and self.cmdargs.apply:
            result = net_connect.save_config()
            self.subs.verbose_printer("{} - {}".format(ipaddr,result))
        return foundnum,missingnum,appliednum,errornum

    def check_config_for_command(self,command,sh_run):
        escapedcommand = command.translate(str.maketrans({"-": r"\-",
                                                                  "]": r"\]",
                                                                  "\\": r"\\",
                                                                  "^": r"\^",
                                                                  "$": r"\$",
                                                                  "*": r"\*",
                                                                  "+": r"\+",
                                                                  ".": r"\."}))
        if re.search('^\s*{}'.format(escapedcommand), sh_run, flags=re.IGNORECASE | re.MULTILINE):
            return True
        else:
            return False

    def hp_password_change_begin(self):
        if 'apply' in self.cmdargs and self.cmdargs.apply:
            print("Beginning Apply Standards Operation")
        else:
            print("Beginning Check Standards Operation")
            # File will have mandatory first row with at least these fields:  ip, type, user, pass, en, port
        file = open(self.cmdargs.ipfile, "r")
        summary_list = []

        if 'manual' in self.cmdargs and self.cmdargs.manual:
            row_titles = next(file).split(
                ',')  # grab the first row (the titles) use these to make the standardize switch call dynamic
            row_titles[len(row_titles) - 1] = row_titles[len(row_titles) - 1].rstrip()  # remove the trailing newline

        for ip in file:
            if ('manual' in self.cmdargs and self.cmdargs.manual and len(
                    row_titles) == 6):  # {IP][Vendor][UN][PW][EN][PORT.split]
                ip_entry = ip.split(',')
                if (len(ip_entry) == len(row_titles)):
                    ip_entry[len(ip_entry) - 1] = ip_entry[len(ip_entry) - 1].rstrip()
                    summary_list.append(
                        self.HP_Pass_Change(ip_entry[row_titles.index("ip")], ip_entry[row_titles.index("type")],
                                                ip_entry[row_titles.index("user")], ip_entry[row_titles.index("pass")],
                                                ip_entry[row_titles.index("en")], ip_entry[row_titles.index("port")]))
            elif 'manual' in self.cmdargs and not self.cmdargs.manual:
                try:
                    vendor = self.subs.snmp_get_vendor_string(ip.rstrip())
                    if vendor == "Cisco":
                        device_type = "cisco_ios"
                    elif vendor == "HP":
                        device_type = "hp_procurve"
                    else:
                        device_type = "generic_termserver"
                    summary_list.append(
                        self.HP_Pass_Change(ip.rstrip(), device_type, self.config.username, self.config.password,
                                                self.config.enable_pw, 22))
                except Exception as err:
                    print(err)
        file.close()
        print("\nSUMMARY:")
        for entry in summary_list:
            print(entry)

    def HP_Pass_Change(self,ipaddr,vendor,username,password,enable_pw,port):
        print_summary = ""
        if self.subs.ping_check(ipaddr):
            try:
                if "hp_procurve_telnet" in vendor:
                    net_connect = self.subs.create_connection_manual(ipaddr, vendor, username, password, enable_pw, port, "sername","assword")
                else:
                    net_connect = self.subs.create_connection_custom(ipaddr, vendor, username, password, enable_pw,
                                                                     port)
                if 'manual' in self.cmdargs and self.cmdargs.manual:
                    enable_success = self.subs.vendor_enable_manual(vendor, net_connect, username, password, enable_pw)
                else:
                    enable_success = self.subs.vendor_enable(vendor, net_connect)
                if enable_success:
                    if 'apply' in self.cmdargs and self.cmdargs.apply:
                        result = net_connect.send_command("conf t","#")
                        result += net_connect.send_command("pass manager user-name {}".format(self.cmdargs.username), ":")
                        result += net_connect.send_command("{}".format(self.cmdargs.password), ":")
                        result += net_connect.send_command("{}".format(self.cmdargs.password), "#")
                        result += net_connect.save_config()
                        self.subs.verbose_printer("{} - {}".format(ipaddr,result))
                        self.subs.verbose_printer("{} - Updated password".format(ipaddr))
                        return "{} - Updated password".format(ipaddr)
                    else:
                        self.subs.verbose_printer("{} - Logged in successfully, but did not change Password".format(ipaddr))
                        return "{} - Logged in successfully, but did not change Password".format(ipaddr)
                else:
                    self.subs.verbose_printer("###{}### ERROR Unable to enable".format(ipaddr))
                    return "{} - Unable to Enable".format(ipaddr)
                net_connect.disconnect()
            except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                self.subs.verbose_printer(err.args[0], "###{}### ERROR Netmiko Authentication Failure ".format(ipaddr))
                return "{} - {}".format(ipaddr, err.args[0])
            except netmiko.ssh_exception.NetMikoTimeoutException as err:
                self.subs.verbose_printer(err.args[0], "###{}### ERROR Netmiko Timeout Failure".format(ipaddr))
                return "{} - {}".format(ipaddr, err.args[0])
            except netmiko.ssh_exception.SSHException as err:
                if (err.args[0] == "Incompatible version (1.5 instead of 2.0)"):
                    self.subs.verbose_printer(err.args[0], "###{}### ERROR Netmiko incompatible version".format(ipaddr))
                    result2 = self.HP_Pass_Change(ipaddr, "{}_telnet".format(vendor), username, password, enable_pw, 23) # try telnet if v1 only
                    return "{} - {}\n{} - {}".format(ipaddr, err.args[0], ipaddr,result2)
                else:
                    self.subs.verbose_printer(err.args[0], "###{}### ERROR Netmiko SSH Exception".format(ipaddr))
                    return "{} - {}".format(ipaddr, err.args[0])
            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                self.subs.verbose_printer("###{}### ERROR NETMIKO:{}".format(ipaddr, err.args[0]))
                return "{} - {}".format(ipaddr, err.args[0])

        else:
            self.subs.verbose_printer("####{}### ERROR Unable to ping ".format(ipaddr))
            return "{} - No Ping Response".format(ipaddr)

    def arp_table_check(self):
        cmdlist = []

        file = open(os.path.join(self.cmdargs.cmdfile), "r")
        self.subs.verbose_printer("##### file opened:{} #####".format(file))

        for cmd in file:
            cmdlist.append(cmd.rstrip())
        file.close()

        if self.subs.ping_check(self.cmdargs.ipaddr):
            try:
                net_connect = self.subs.create_connection(self.cmdargs.ipaddr) #added this
                if net_connect:
                    output = net_connect.send_command("term length 0")
                    for cmd in cmdlist:

                        # Show Interface Status
                        self.subs.custom_printer("verbose", "show ip arp {}".format(cmd))
                        output = net_connect.send_command("show ip arp {}".format(cmd))
                        # example output: 2044    0000.AAAA.BBBB    DYNAMIC     Po9
                        if 'csv' in self.cmdargs and self.cmdargs.csv:
                            outputlist = output.splitlines()
                            for line in outputlist:
                                if 'filter' in self.cmdargs and self.cmdargs.filter is not None:
                                    filterlist = self.cmdargs.filter.split(',')

                                    if not any([x in line for x in filterlist]):
                                        csv = re.sub("\s+", ",", line)
                                        print("{},{},{}".format(self.cmdargs.ipaddr, cmd, csv))
                                else:
                                    csv = re.sub("\s+", ",", line)
                                    print("{},{},{}".format(self.cmdargs.ipaddr,cmd,csv))
                        else:
                            print(output)
            except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                self.subs.verbose_printer(err.args[0],"Netmiko Authentication Failure")
            except netmiko.ssh_exception.NetMikoTimeoutException as err:
                self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
            except ValueError as err:
                #if 'verbose' in self.cmdargs and self.cmdargs.verbose:
                print(err.args[0])


    def mac_table_check(self):
        iplist = []

        file = open(os.path.join(self.cmdargs.ipfile), "r")
        self.subs.verbose_printer("##### file opened:{} #####".format(file))
        for ip in file:
            iplist.append(ip.rstrip())
        file.close()


        for ip in iplist:
            if self.subs.ping_check(ip):
                try:
                    net_connect = self.subs.create_connection(ip)  # added this
                    if net_connect:
                        output = net_connect.send_command("term length 0")

                        # Show Interface Status
                        self.subs.custom_printer("verbose", "show mac addr")
                        output = net_connect.send_command("show mac addr")
                        if 'csv' in self.cmdargs and self.cmdargs.csv:
                            outputlist = output.splitlines()
                            for line in outputlist:
                                if 'filter' in self.cmdargs and self.cmdargs.filter is not None:
                                    filterlist = self.cmdargs.filter.split(',')

                                    if not any([x in line for x in filterlist]):
                                        csv = re.sub("\s+", ",", line.strip())
                                        print("{},{}".format(ip, csv))
                                else:
                                    csv = re.sub("\s+", ",", line.strip())
                                    print("{},{}".format(ip, csv))


                        else:
                            print(output)
                except netmiko.ssh_exception.NetMikoAuthenticationException as err:
                    self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
                except netmiko.ssh_exception.NetMikoTimeoutException as err:
                    self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
                except ValueError as err:
                    # if 'verbose' in self.cmdargs and self.cmdargs.verbose:
                    print(err.args[0])




