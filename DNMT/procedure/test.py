#!/usr/bin/env python3

import re
import sys
import subprocess,platform,os,time,datetime
import getpass
import difflib
import smtplib
import tempfile
import zipfile
from email import encoders
from email.message import EmailMessage
import pickle,bz2 #imports for statchecks

import zipfile #imports for summary filescompression imports






#3rd party imports
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import netmiko
from pathos.multiprocessing import ProcessingPool as Pool

#local subroutine import
from DNMT.procedure.subroutines import SubRoutines



class Test:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        self.log_path = os.path.abspath(os.path.join(os.sep, 'var', 'log', 'dnmt'))
        self.successful_switches = [] #used for activity tracking
        self.failure_switches = [] #used for activity tracking
       # self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
        #                                   datetime.date.today().strftime('%Y%m%d'))


    def Switch_Check(self):
        #3560X with ten gig uplink doesn't show gi 1/1-2 only ten 1/1-2.
        if 'load' in self.cmdargs and self.cmdargs.load is not None:
            try:
                # LOADING Compressed files
                with bz2.open(self.cmdargs.load, "rb") as f:
                    test = pickle.load(f, encoding='utf-8')

            except FileNotFoundError:
                print("##### {} -  No file found #####".format(self.cmdargs.load))
            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                print("FILE ERROR {}".format( err.args[0]))
        elif 'ipaddr' in self.cmdargs and self.cmdargs.ipaddr is not None:
            start = time.time()
            test = self.subs.snmp_get_switch_data_full(self.cmdargs.ipaddr)
            end = time.time()
            print("time:{} seconds".format(int((end-start)*100)/100))
        else:
            print("Invalid Syntax, need to specify an IP with -i or a file to check with -l")
            sys.exit(1)
        # test.printStack()
        # test.printSingleLine()
        if 'csv' in self.cmdargs and self.cmdargs.csv is not None:
            test.exportCSV(self.cmdargs.csv)
        else:
            test.printStack()

    def Error_Check(self):
        error_dict = {"ip": self.cmdargs.ipaddr}
        intId = self.subs.snmp_get_interface_id(self.cmdargs.ipaddr,self.cmdargs.interface)
        self.subs.verbose_printer("interface ID:{}".format(intId))
        error_dict["input errors"] = self.subs.snmp_get_input_errors_by_id(self.cmdargs.ipaddr,intId)
        error_dict["output errors"] = self.subs.snmp_get_output_errors_by_id(self.cmdargs.ipaddr, intId)
        error_dict["crc errors"] = self.subs.snmp_get_crc_errors_by_id(self.cmdargs.ipaddr, intId)
        for entry in error_dict:
            print("{}:{}".format(entry, error_dict[entry]))

    def Command_Blaster_Begin(self):

        #Make Command List
        commandlist = []
        file = open(self.cmdargs.commandfile, "r")
        for ip in file:
            commandlist.append(ip.rstrip())
        file.close()

        #Iterate through addresses List
        file = open(self.cmdargs.ipaddrfile, "r")
        for ip in file:
            self.Command_Blast(ip.rstrip(), commandlist)
        file.close()



    def Command_Blast(self,ipaddr,commandlist):
        # SSH Connection
        try:
            net_connect = self.subs.create_connection(ipaddr)
            # net_connect = ConnectHandler(**cisco_sw)
            if net_connect:
                ### ADD ERROR HANDLING FOR FAILED CONNECTION
                print("-------- CONNECTED TO {} --------".format(ipaddr))

                for command in commandlist:
                    result = net_connect.send_command(command)
                    print("COMMAND:{}\nRESPONSE:{}".format(command,result))
                net_connect.disconnect()
            else:
                print("-------- FAILED TO CONNECTED TO {} --------".format(ipaddr))
        except netmiko.ssh_exception.NetMikoAuthenticationException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
        except netmiko.ssh_exception.NetMikoTimeoutException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
        except ValueError as err:
            print(err.args[0])
        except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
            print("NETMIKO ERROR {}:{}".format(ipaddr, err.args[0]))

    def BadPhoneBegin(self):
        iplist = []
        file = open(self.cmdargs.file, "r")
        for ip in file:
            iplist.append(ip.rstrip())
        file.close()

        for ip in iplist:
            self.BadPhoneFinder(ip)

    def BadPhoneFinder(self,ipaddr):
        try:
            # test = self.subs.snmp_get_mac_table_bulk(self.cmdargs.ipaddr)
            # test1 = self.subs.snmp_get_switch_data_full(self.cmdargs.ipaddr)
            net_connect = self.subs.create_connection(ipaddr)
            if net_connect:
                sw_dict = {"ip": ipaddr}
                sw_dict["int_return"] = net_connect.send_command('show power inline | include Ieee')
                sw_dict["int_list"] = re.findall('(?:\s*)(\S+)(?:\s+.*)', sw_dict["int_return"], re.VERBOSE | re.MULTILINE)
                if len(sw_dict["int_list"]) is not 0:
                    print("{} --- {} Ieee interfaces found".format(sw_dict["ip"], len(sw_dict["int_list"])))
                    for interface in sw_dict["int_list"]:
                        int_status = net_connect.send_command('show int {}'.format(interface)).split("\n")[0]

                        if "notconnect" in int_status:
                            if 'skip' in self.cmdargs and not self.cmdargs.skip:
                                response = input("{} --- {} is showing NotConnected, toggle port on/off ('yes'):".format(sw_dict["ip"], interface))
                                if not response == 'yes':
                                    self.subs.verbose_printer('Did not proceed with change.')
                                    sys.exit(1)
                            self.subs.snmp_reset_interface(ipaddr,
                                                           self.subs.snmp_get_interface_id(ipaddr,
                                                                                           interface))
                            print("{} --- {} interface restarted".format(sw_dict["ip"], interface))


                        else:
                            print("{} --- {} Port is showing connected".format(sw_dict["ip"],interface))
                else:
                    print("{} --- No Ieee entries found".format(sw_dict["ip"]))


            net_connect.disconnect()
                # netmiko connection error handling
        except netmiko.ssh_exception.NetMikoAuthenticationException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Authentication Failure")
        except netmiko.ssh_exception.NetMikoTimeoutException as err:
            self.subs.verbose_printer(err.args[0], "Netmiko Timeout Failure")
        except ValueError as err:
            print(err.args[0])
        except Exception as err: #currently a catch all to stop linux from having a conniption when reloading
            print("NETMIKO ERROR {}:{}".format(ipaddr,err.args[0]))

    def Activity_Tracking_Begin(self):
        iplist = []
        total_start = time.time()
        if not os.path.exists(os.path.join(self.log_path, "activitycheck", "rawfiles")):
            os.makedirs(os.path.join(self.log_path, "activitycheck", "rawfiles"))
        if not os.path.exists(os.path.join(self.log_path, "activitycheck", "processedfiles")):
            os.makedirs(os.path.join(self.log_path, "activitycheck", "processedfiles"))
        # Specifying a file only changes what IPs are updated, right now the status check grabs all existing files in
        # the raw data folder
        try:
            if 'file' in self.cmdargs and self.cmdargs.file is not None:
                file = open(os.path.join(self.cmdargs.file), "r")
            else:
                file = open(os.path.abspath(os.path.join(os.sep, 'usr', 'lib', 'capt', "activitycheckIPlist")), "r")
            self.subs.verbose_printer("##### file opened:{} #####".format(file))

            for ip in file:
                iplist.append(ip.rstrip())
            file.close()

            # pool = Pool(len(iplist))  # 4 concurrent processes
            # results = pool.map(self.single_search, iplist)

            #TODO CHANGE to do them with individual processes
            if 'check' in self.cmdargs and self.cmdargs.check is False:
                # pool = Pool(len(iplist))  # 4 concurrent processes
                if 'parallel' in self.cmdargs and self.cmdargs.parallel is True:
                    if 'numprocs' in self.cmdargs and self.cmdargs.numprocs is False:
                        numprocs = 5
                    else:
                        if self.cmdargs.numprocs == "all":
                            numprocs = len(iplist)
                        else:
                            try:
                                numprocs = int(self.cmdargs.numprocs)
                            except ValueError:
                                self.subs.verbose_printer("numprocs is not a number, defaulting to 5!")
                                numprocs = 5
                            except Exception:
                                numprocs = 5 #catch all if things go sideways
                    pool = Pool(numprocs)
                    pool.map(self.Activity_Tracking,iplist)
                else:
                    for ip in iplist:
                        try:
                            self.Activity_Tracking(ip)
                        except Exception as err:
                            print("ERROR PROCESSING FILE {}:{}".format(ip, err))
            self.subs.verbose_printer("##### Total Processing Complete, Total Time:{} seconds #####".format( int((time.time() - total_start) * 100) / 100))
        except FileNotFoundError:
            print("##### ERROR iplist files not found #####")
        except Exception as err:
            print ("##### ERROR with processing:{} #####".format(err))

        # After all processes return, read in each pickle and create a single output file?
        status_filename = "{}-FullStatus.csv".format(datetime.date.today().strftime('%Y-%m-%d'))
        try:
            self.Create_Readable_Activity_File(status_filename,iplist)
        except Exception as err:
            print("##### ERROR creating Summary File: {} #####".format(err))

        #Compress
        # with open(os.path.join(self.log_path, "activitycheck", "processedfiles", status_filename), 'rb') as f_in:
        #     with gzip.open(os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.gz".format(status_filename)), 'wb') as f_out:
        #         shutil.copyfileobj(f_in, f_out)
        #EMail finished file:
        try:
            self.subs.verbose_printer("##### Emailing now #####")

            zf = open(os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.zip".format(status_filename)), 'rb')


            temp_from = "admin@localhost"
            if 'email' in self.cmdargs and self.cmdargs.email is not None:
               temp_to = self.cmdargs.email
            else:
                temp_to = "mandzie@ualberta.ca"

            # Create the message
            themsg = MIMEMultipart()
            themsg["From"] = temp_from
            themsg["Subject"] = "updated activitycheck - {}".format(datetime.date.today().strftime('%Y-%m-%d'))
            themsg["To"] = temp_to
            themsg["Body"]="Processing completed in {} seconds\n{} switches SUCCESSFULLY processed\n{} switches FAILED during processing\n ".format(
                 int((time.time() - total_start) * 100) / 100, len(self.successful_switches),len(self.failure_switches) )


            themsg.preamble = 'I am not using a MIME-aware mail reader.\n'
            msg = MIMEBase('application', 'zip')
            msg.set_payload(zf.read())
            encoders.encode_base64(msg)
            msg.add_header('Content-Disposition', 'attachment',
                           filename=status_filename + '.zip')


            themsg.attach(msg)

            # TODO add failed collections to be printed in the body of the email
            # body = "Processing completed in {} seconds\n{} switches SUCCESSFULLY processed\n{} switches FAILED during processing\n ".format(
            #     int((time.time() - total_start) * 100) / 100, len(self.), )
            # themsg.attach(MIMEText(body, 'plain'))

            themsg = themsg.as_string()

            # send the message
            smtp = smtplib.SMTP()
            smtp.connect()
            smtp.sendmail(temp_from, temp_to, themsg)
            smtp.close()

        except smtplib.SMTPException:
            print("Failed to send Email")
        except Exception as err:
            print(err)


    def Create_Readable_Activity_File(self,status_filename,iplist):
        TotalStatus = "IP,Vendor,Hostname,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE,CDP,Status (1=Up),DataVlan,VoiceVlan,Mode,IntID,InputErrors,OutputErrors,InputCounters,OutputCounters,LastTimeUpdated,DeltaInputCounters,DeltaOutputCounters\n"
        #Currently grabs all existing statcheck files, this could be changed to only act on the iplist provided
        if 'limit' in self.cmdargs and self.cmdargs.limit is True:
            self.subs.verbose_printer("##### Creating Limited Summary List #####")
            for ip in iplist:
                #process
                try:
                    # with open(file, "rb") as myNewFile:
                    # LOADING Compressed files
                    with bz2.open(
                            os.path.join(self.log_path, "activitycheck", "rawfiles", "{}-statcheck.bz2".format(ip)),
                            "rb") as f:
                        SwitchStatus = pickle.load(f, encoding='utf-8')
                        TotalStatus += SwitchStatus.appendSingleLine()
                except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                    print("FILE ERROR {}-statcheck:{}".format(ip, err.args[0]))
        else:
            self.subs.verbose_printer("##### Creating Full Summary List #####")
            for file in os.listdir(os.path.join(self.log_path,"activitycheck", "rawfiles")):
                if file.endswith("-statcheck.bz2"):
                    #process
                    try:
                        # with open(file, "rb") as myNewFile:
                        with bz2.open(os.path.join(self.log_path, "activitycheck","rawfiles", file), "rb") as f:
                            SwitchStatus = pickle.load(f)
                            TotalStatus += SwitchStatus.appendSingleLine()
                    except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                        print("FILE ERROR {}:{}".format(file, err.args[0]))


        # with open(os.path.join(self.log_path, "activitycheck", "processedfiles", status_filename), 'w',
        #           encoding='utf-8') as filePointer:
        #     print(TotalStatus, file=filePointer)


        # with gzip.GzipFile(os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.gz".format(status_filename)), 'wb') as f:
        #     f.write(TotalStatus.encode("utf-8")


        with bz2.BZ2File(os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.bz2".format(status_filename)),
                         'wb') as sfile:
            sfile.write(TotalStatus.encode("utf-8"))

        zf = zipfile.ZipFile(os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.zip".format(status_filename)),
                             mode='w',
                             compression=zipfile.ZIP_DEFLATED,
                             )
        try:
            zf.writestr(status_filename, TotalStatus)
        finally:
            zf.close()



    def Activity_Tracking_Comparison(self, newval,historicalvals,maxvals):
        if newval is not None:  # ensure there are new entries
            if len(historicalvals) != 0:  # make sure there are existing historical entries
                if newval != historicalvals[
                    len(historicalvals)-1][1]:  # dont add duplicates
                    if len(historicalvals) >= maxvals:
                        historicalvals = historicalvals[1:]
                    historicalvals.append(
                        (int(datetime.datetime.now().strftime("%Y%m%d%H%M")), newval))
            else:
                historicalvals.append(
                    (int(datetime.datetime.now().strftime("%Y%m%d%H%M")), newval))
        return historicalvals

    def Activity_Tracking(self,ipaddr):
    # this function will:
    # -grab the current status,
    # -load a pickled switch status if there is one, create one if there is not
    #   -Pickled switch status will also include:
    #       -For Ports - (Time last changed} last change in state (append date for first entry, append if changed)
    #       -For Ports - (Delta In from last change) if changed from last check
    #       -For Ports - (Delta Out from last change) if changed from last check
    #
    # TODO
    #   -Determine where these log files should go
        start = time.time()
        self.subs.verbose_printer("##### {} -  Processing #####".format(ipaddr))
        NewSwitchStatus  = self.subs.snmp_get_switch_data_full(ipaddr)

    #TODO Check if a previous static check exists, and load it if it does, otherwise create it and write it out
        try:

            with bz2.open(os.path.join(self.log_path, "activitycheck", "rawfiles","{}-statcheck.bz2".format(ipaddr)), "rb") as myNewFile:
                OldSwitchStatus = pickle.load(myNewFile)

            for tempswitch in OldSwitchStatus.switches:
                for tempmodule in tempswitch.modules:
                    for oldport in tempmodule.ports:
                        newport = NewSwitchStatus.getPortById(oldport.intID)
                        if oldport.activityChanged(newport):
                            oldport.deltalastin = newport.inputcounters - oldport.inputcounters
                            oldport.deltalastout = newport.outputcounters - oldport.outputcounters
                            oldport.cdp = newport.cdp
                            oldport.poe = newport.poe
                            oldport.status = newport.status
                            oldport.inputerrors = newport.inputerrors
                            oldport.outputerrors = newport.outputerrors
                            oldport.inputcounters = newport.inputcounters
                            oldport.outputcounters = newport.outputcounters
                            oldport.lastupdate = datetime.date.today().strftime('%Y-%m-%d')

                            oldport.historicalinputerrors = self.Activity_Tracking_Comparison(newport.inputerrors, oldport.historicalinputerrors, newport.maxhistoricalentries)
                            oldport.historicaloutputerrors = self.Activity_Tracking_Comparison(newport.outputerrors, oldport.historicaloutputerrors, newport.maxhistoricalentries)
                            oldport.historicalinputcounters = self.Activity_Tracking_Comparison(newport.inputcounters, oldport.historicalinputcounters, newport.maxhistoricalentries)
                            oldport.historicaloutputcounters = self.Activity_Tracking_Comparison(newport.outputcounters, oldport.historicaloutputcounters, newport.maxhistoricalentries)

            #TODO Compare the two files now
            self.successful_switches.append(ipaddr)

        except FileNotFoundError:
            print("##### {} -  No previous status file found, one will be created #####".format(ipaddr))
            OldSwitchStatus = NewSwitchStatus

            for tempswitch in OldSwitchStatus.switches:
                for tempmodule in tempswitch.modules:
                    for tempport in tempmodule.ports:
                        tempport.lastupdate = datetime.date.today().strftime('%Y-%m-%d')
                        tempport.deltalastin = 0
                        tempport.deltalastout = 0
            self.successful_switches.append(ipaddr)


        except Exception as err: #currently a catch all to stop linux from having a conniption when reloading
            print("FILE ERROR {}:{}".format(ipaddr,err.args[0]))
            self.failure_switches.append(ipaddr)


# Saving Compressed files
        with bz2.BZ2File(os.path.join(self.log_path,"activitycheck", "rawfiles","{}-statcheck.bz2".format(ipaddr)), 'wb') as sfile:
            pickle.dump(OldSwitchStatus, sfile)

        end = time.time()
        self.subs.verbose_printer("##### {} -  Processing Complete, time:{} seconds #####".format(ipaddr, int((end - start) * 100) / 100))

