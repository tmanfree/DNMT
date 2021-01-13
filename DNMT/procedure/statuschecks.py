#!/usr/bin/env python3

import re
import sys
import subprocess,platform,os,time,datetime
import getpass
import difflib
import smtplib
import tempfile
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



class StatusChecks:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        # self.log_path = os.path.abspath(os.path.join(os.sep, 'var', 'log', 'dnmt'))
        # self.subs.log_path = os.path.abspath(os.path.join(os.sep, 'var', 'log', 'dnmt'))
        self.successful_switches = [] #used for activity tracking
        self.failure_switches = [] #used for activity tracking
        self.successful_files = []#used for activity tracking
        self.failure_files = []  # used for activity tracking

    def Maintenance(self,maxfiles):
        #
        self.subs.verbose_printer("##### Cleaning up files #####")

        #Remove oldest files (listed first on windows
        filelist = os.listdir(os.path.join(self.subs.log_path, "activitycheck", "processedfiles"))
        if len(filelist) > 0 and len(filelist) > maxfiles:
            # self.subs.verbose_printer("##### unsorted list:{} #####".format(filelist))
            sortedfilelist = sorted(filelist)
            # self.subs.verbose_printer("##### sorted list:{} #####".format(testlist))
            filestoremove = sortedfilelist[0:(len(filelist)-maxfiles)]
            self.subs.verbose_printer("total files:{}\nremoving files:{}".format(len(filelist),len(filestoremove)))
            for file in filestoremove:
                if file.endswith("-FullStatus.csv.zip"):
                    # process
                    try:
                        self.subs.verbose_printer("##### File to remove:{} #####".format(file))
                        if 'test' in self.cmdargs and self.cmdargs.test is False :
                            self.subs.verbose_printer("##### Removing file:{} #####".format(file))
                            os.remove(os.path.join(self.subs.log_path, "activitycheck", "processedfiles",file))
                    except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                        print("FILE ERROR {}:{}".format(file, err.args[0]))
                        self.failure_files.append(file)
        else:
            self.subs.verbose_printer("total files:{} are less than max value:{}".format(len(filelist), maxfiles))

    def Activity_Tracking_Begin(self):
        iplist = []
        total_start = time.time()
        if not os.path.exists(os.path.join(self.subs.log_path, "activitycheck", "rawfiles")):
            self.subs.custom_printer("debug","## DBG - Creating activitycheck/rawfiles directory ##")
            os.makedirs(os.path.join(self.subs.log_path, "activitycheck", "rawfiles"))
        if not os.path.exists(os.path.join(self.subs.log_path, "activitycheck", "processedfiles")):
            self.subs.custom_printer("debug", "## DBG - Creating activitycheck/processedfiles directory ##")
            os.makedirs(os.path.join(self.subs.log_path, "activitycheck", "processedfiles"))
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
                    results = pool.map(self.Activity_Tracking,iplist)
                    for result in results:
                        if result[0]:
                            self.successful_switches.append(result[1])
                        else:
                            self.failure_switches.append(result[1])
                else:
                    for ip in iplist:
                        try:
                            result = self.Activity_Tracking(ip)
                            if result[0]:
                                self.successful_switches.append(result[1])
                            else:
                                self.failure_switches.append(result[1])
                        except Exception as err:
                            print("ERROR PROCESSING FILE {}:{}".format(ip, err))
            self.subs.verbose_printer("##### Total Processing Complete, Total Time:{} seconds #####".format( int((time.time() - total_start) * 100) / 100))
        except FileNotFoundError:
            print("##### ERROR iplist files not found #####")
        except Exception as err:
            print ("##### ERROR with processing:{} #####".format(err))

        # After all processes return, read in each pickle and create a single output file?
        status_filename = "{}-FullStatus.csv".format(datetime.datetime.now().strftime('%Y-%m-%d-%H%M'))
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

            zf = open(os.path.join(self.subs.log_path, "activitycheck", "processedfiles", "{}.zip".format(status_filename)), 'rb')


            temp_from = "admin@localhost"
            if 'email' in self.cmdargs and self.cmdargs.email is not None:
               temp_to = self.cmdargs.email
            else:
                temp_to = "admin@localhost" #placeholder

            # Create the message
            themsg = MIMEMultipart()
            themsg["From"] = temp_from
            themsg["Subject"] = "updated activitycheck - {}".format(datetime.date.today().strftime('%Y-%m-%d'))
            themsg["To"] = temp_to
            # themsg["Body"]="Processing completed in {} seconds\n{} switches SUCCESSFULLY processed\n{} switches FAILED during processing\n ".format(
            #      int((time.time() - total_start) * 100) / 100, len(self.successful_switches),len(self.failure_switches) )


            themsg.preamble = 'I am not using a MIME-aware mail reader.\n'
            msg = MIMEBase('application', 'zip')
            msg.set_payload(zf.read())
            encoders.encode_base64(msg)
            msg.add_header('Content-Disposition', 'attachment',
                           filename=status_filename + '.zip')


            themsg.attach(msg)

            #create the body of the email
            body = "Processing completed in {} seconds\n".format(int((time.time() - total_start) * 100) / 100)
            body += "{} switch state files SUCCESSFULLY updated\n".format(len(self.successful_switches))
            body += "{} switch state files FAILED to update\n" .format(len(self.failure_switches))
            body += "{} switch states SUCCESSFULLY added to the summary file\n".format(len(self.successful_files))
            body += "{} switch states FAILED to add to the summary file\n".format( len(self.failure_files))
            body += "\n--------------------------------------------------------------------------------------\n\n"

            if len(self.successful_switches) > 0:
                body += "--- List of switch statuses SUCCESSFULLY updated ---\n"
                for entry in self.successful_switches:
                    body += "{}\n".format(entry)
            if len(self.failure_switches) > 0:
                body += "--- List of switch statuses that FAILED to update ---\n"
                for entry in self.failure_switches:
                    body += "{}\n".format(entry)
            if len(self.successful_files) > 0:
                body += "--- List of files SUCCESSFULLY added to summary file ---\n"
                for entry in self.successful_files:
                    body += "{}\n".format(entry)
            if len(self.failure_files) > 0:
                body += "--- List of files FAILED to be added to summary file ---\n"
                for entry in self.failure_files:
                    body += "{}\n".format(entry)

            themsg.attach(MIMEText(body, 'plain'))

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
        if 'xecutive' in self.cmdargs and self.cmdargs.xecutive is True:
            TotalStatus = "IP,Vendor,Hostname,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE draw (1=Yes),Status (1=Up),DataVlan,DataVlan name,VoiceVlan,Mode (1=Trunk),PsViolations,InputErrors,OutputErrors,InputCounters,OutputCounters,LastTimeUpdated,DeltaInputCounters,DeltaOutputCounters\n"
        else:
            TotalStatus = "IP,Vendor,Hostname,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE,Neighbour name,Neighbour port,Neighbour type,Status (1=Up),DataVlan,DataVlan name,VoiceVlan,Mode (1=Trunk),IntID,PsViolations,InputErrors,OutputErrors,InputCounters,OutputCounters,LastTimeUpdated,DeltaInputCounters,DeltaOutputCounters,HistoricalInputErrors,HistoricalOutputErrors,HistoricalInputCounters,HistoricalOutputCounters\n"
        #By default grabs all existing statcheck files, this could be changed to only act on the iplist provided


        if 'limit' in self.cmdargs and self.cmdargs.limit is True:
            self.subs.verbose_printer("##### Creating Limited Summary List #####")
            fileList = [f+"-statcheck.bz2" for f in iplist]
        else:
            self.subs.verbose_printer("##### Creating Full Summary List #####")
            fileList = [f for f in os.listdir(os.path.join(self.subs.log_path,"activitycheck", "rawfiles","active")) if f.endswith('-statcheck.bz2')]
        for ip in fileList:
            # process
            try:
                # LOADING Compressed files
                self.subs.custom_printer("debug", "## DBG - Opening pickled file from active for {} ##".format(ip))
                with bz2.open(os.path.join(self.subs.log_path, "activitycheck", "rawfiles", "active", ip), "rb") as f:
                    self.subs.custom_printer("debug", "## DBG - loading pickled file from active for {} ##".format(ip))
                    SwitchStatus = pickle.load(f, encoding='utf-8')
                    if 'xecutive' in self.cmdargs and self.cmdargs.xecutive is True:
                        TotalStatus += SwitchStatus.appendSingleLineExec()
                    else:
                        TotalStatus += SwitchStatus.appendSingleLine()
                    self.subs.custom_printer("debug", "## DBG - Appending {} to successful files ##".format(ip))
                    self.successful_files.append("{}-statcheck.bz2".format(ip))
            except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                print("FILE ERROR {}-statcheck:{}".format(ip, err.args[0]))
                self.subs.custom_printer("debug", "## DBG - Error in create readable activity file ##")
                self.failure_files.append("{}-statcheck.bz2".format(ip))

        ## Works, but emailing is a pain
        # with bz2.BZ2File(os.path.join(self.log_path, "activitycheck", "processedfiles", "{}.bz2".format(status_filename)),
        #                  'wb') as sfile:
        #     sfile.write(TotalStatus.encode("utf-8"))

        zf = zipfile.ZipFile(os.path.join(self.subs.log_path, "activitycheck", "processedfiles", "{}.zip".format(status_filename)),
                             mode='w',
                             compression=zipfile.ZIP_DEFLATED,
                             )
        try:
            zf.writestr(status_filename, TotalStatus)
        finally:
            zf.close()


#Activity_Tracking_Comparison(porttwo.inputerrors,portone.historicalinputerrors,portone.maxhistoricalentries)
    def Activity_Tracking_Comparison(self, newval,historicalvals,maxvals):
        if newval is not None:  # ensure there are new entries
            if len(historicalvals) != 0:  # make sure there are existing historical entries
                if newval != historicalvals[len(historicalvals)-1][1]:  # dont add duplicates
                    if len(historicalvals) >= maxvals:
                        historicalvals = historicalvals[(len(historicalvals) - maxvals)+1:]   #currently cuts one off
                    historicalvals.append(
                        (int(datetime.datetime.now().strftime("%Y%m%d%H%M")), newval))
            else:
                historicalvals.append(
                    (int(datetime.datetime.now().strftime("%Y%m%d%H%M")), newval))
        return historicalvals

    def Port_Update_Historical_Counters(self,portone,porttwo):
        if 'maxentries' in self.cmdargs and self.cmdargs.maxentries is not None:
            if self.cmdargs.maxentries.isdigit():
                portone.maxhistoricalentries = int(self.cmdargs.maxentries)
            else:
                self.subs.verbose_printer("max entries cmdarg is not a number")

        portone.historicalinputerrors = self.Activity_Tracking_Comparison(portone.inputerrors,
                                                                          porttwo.historicalinputerrors,
                                                                          portone.maxhistoricalentries)
        portone.historicaloutputerrors = self.Activity_Tracking_Comparison(portone.outputerrors,
                                                                           porttwo.historicaloutputerrors,
                                                                           portone.maxhistoricalentries)
        portone.historicalinputcounters = self.Activity_Tracking_Comparison(portone.inputcounters,
                                                                            porttwo.historicalinputcounters,
                                                                            portone.maxhistoricalentries)
        portone.historicaloutputcounters = self.Activity_Tracking_Comparison(portone.outputcounters,
                                                                             porttwo.historicaloutputcounters,
                                                                             portone.maxhistoricalentries)

    def Port_Updating_Active(self, portone,porttwo):
        portone.deltalastin = portone.inputcounters - porttwo.inputcounters
        portone.deltalastout = portone.outputcounters - porttwo.outputcounters
        portone.lastupdate = datetime.date.today().strftime('%Y-%m-%d')
        self.Port_Update_Historical_Counters(portone,porttwo)



    def Port_Updating_Archive(self, portone,porttwo):
        portone.deltalastin = porttwo.deltalastin
        portone.deltalastout = porttwo.deltalastout
        portone.cdpname = porttwo.cdpname
        portone.cdpport = porttwo.cdpport
        portone.cdptype = porttwo.cdptype
        portone.poe = porttwo.poe
        portone.description = porttwo.description
        portone.datavlan = porttwo.datavlan
        portone.datavlanname = porttwo.datavlanname
        portone.voicevlan = porttwo.voicevlan
        portone.status = porttwo.status
        portone.portmode = porttwo.portmode
        portone.inputerrors = porttwo.inputerrors
        portone.outputerrors = porttwo.outputerrors
        portone.inputcounters = porttwo.inputcounters
        portone.outputcounters = porttwo.outputcounters
        portone.lastupdate = porttwo.lastupdate
        portone.historicalinputerrors = porttwo.historicalinputerrors
        portone.historicaloutputerrors = porttwo.historicaloutputerrors
        portone.historicalinputcounters = porttwo.historicalinputcounters
        portone.historicaloutputcounters = porttwo.historicaloutputcounters

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
        #Wrapping everything in a try catch for multiprocessing purposes
        try:
            start = time.time()
            self.subs.verbose_printer("##### {} -  Processing #####".format(ipaddr))
            self.subs.custom_printer("debug", "## DBG - Grabbing switch data through SNMP ##")
            NewSwitchStatus  = self.subs.snmp_get_switch_data_full(ipaddr)


        #TODO Check if a previous static check exists, and load it if it does, otherwise create it and write it out
            try:
                if len(NewSwitchStatus.switches) == 0:
                    raise ValueError('##### {} ERROR - No Data in switchstruct #####'.format(ipaddr))

                #load archival information (may have removed switches in it)
                self.subs.custom_printer("debug", "## DBG - Opening statcheck file from legacy ##")
                with bz2.open(os.path.join(self.subs.log_path, "activitycheck", "rawfiles","legacy","{}-statcheck.bz2".format(ipaddr)), "rb") as myNewFile:
                    self.subs.custom_printer("debug", "## DBG - Loading legacy into OldSwitchStatus ##")
                    OldSwitchStatus = pickle.load(myNewFile)

                # if len(OldSwitchStatus.switches) != len(NewSwitchStatus.switches):
                #TODO Check if the existing file is empty or if there is a different number of switches. If empty,save NewSwitcStatus instead
                #If different number, check which switch is which based on serial numbers to try to save historical data?
                #Then write out OldSwitchStatus to a archive file/folder and write the new one out
                #TODO Why not use the newswitch status instead? Data may be lost if a switch is down when the new one is there? could fix that by adding any missing data to the new one?

                #update the new switch status with archival info
                self.subs.custom_printer("debug", "## DBG - Updating switch status with OldSwitchStatus ##")
                for tempswitch in NewSwitchStatus.switches:
                    #if the switchnumber doesn't exist in the archive status file, add it
                    if OldSwitchStatus.getSwitch(tempswitch.switchnumber) is None:
                        OldSwitchStatus.addExistingSwitch(tempswitch) #will be a link, but should be fine
                        # OldSwitchStatus.addExistingSwitch(copy.deepcopy(tempswitch))
                        # OldSwitchStatus.addExistingSwitch(tempswitch.__dict__.copy())
                    else:
                        for tempmodule in tempswitch.modules:
                            for newport in tempmodule.ports:
                                oldport = OldSwitchStatus.getPortByPortName(newport.portname)
                                if oldport is not None: #check if the port exists in archival data
                                    if newport.activityChanged(oldport): #if the port info has changed...
                                        self.Port_Updating_Active(newport, oldport) #update the new port
                                        self.Port_Updating_Archive(oldport, newport)  # update any old ports that exist
                                    else: #otherwise, grab the historical data to paste in here
                                        newport.lastupdate = oldport.lastupdate
                                        newport.deltalastin = oldport.deltalastin
                                        newport.deltalastout = oldport.deltalastout
                                        newport.historicalinputerrors = oldport.historicalinputerrors
                                        newport.historicaloutputerrors = oldport.historicaloutputerrors
                                        newport.historicalinputcounters = oldport.historicalinputcounters
                                        newport.historicaloutputcounters = oldport.historicaloutputcounters
                                else: #if it is a new port entry
                                    newport.lastupdate = datetime.date.today().strftime('%Y-%m-%d')
                                    newport.deltalastin = 0
                                    newport.deltalastout = 0



                #update the old status file for archive. This should prevent losing data if there is an outage during collection
                # for tempswitch in OldSwitchStatus.switches: #remove this stuff, and just update the old with new values after assigning to the new
                #     for tempmodule in tempswitch.modules:
                #         for oldport in tempmodule.ports:
                #             newport = NewSwitchStatus.getPortByPortName(oldport.portname) #Changed 20200601 from id Cisco changing IDs....
                #             if newport is not None: #if the port exists in the new status check to see if it has changed
                #                 if oldport.activityChanged(newport): #if the port has changed, update it, otherwise leave it
                #                     self.Port_Updating_Archive(oldport, newport) #update any old ports that exist for the archive



                #TODO Compare the two files now
                #write out active status for combining into statcheck csv
                self.subs.custom_printer("debug", "## DBG - Opening Active file to save NewSwitchStatus to ##")
                with bz2.BZ2File(
                        os.path.join(self.subs.log_path, "activitycheck", "rawfiles","active", "{}-statcheck.bz2".format(ipaddr)),
                        'wb') as sfile:
                    self.subs.custom_printer("debug", "## DBG - Writing NewSwitchStatus to active statcheck ##")
                    pickle.dump(NewSwitchStatus, sfile)
                    sfile.close()

                #Write out archival switchstatus to load again later
                self.subs.custom_printer("debug", "## DBG - Opening legacy file to save OldSwitchStatus to ##")
                with bz2.BZ2File(
                        os.path.join(self.subs.log_path, "activitycheck", "rawfiles","legacy", "{}-statcheck.bz2".format(ipaddr)),
                        'wb') as sfile:
                    self.subs.custom_printer("debug", "## DBG - Writing OldSwitchStatus to legacy statcheck ##")
                    pickle.dump(OldSwitchStatus, sfile)
                    sfile.close()

                # self.successful_switches.append(ipaddr)
                returnval = (True, ipaddr)
            except FileNotFoundError:
                print("##### {} -  No previous status file found, one will be created #####".format(ipaddr))
                OldSwitchStatus = NewSwitchStatus

                for tempswitch in OldSwitchStatus.switches:
                    for tempmodule in tempswitch.modules:
                        for tempport in tempmodule.ports:
                            tempport.lastupdate = datetime.date.today().strftime('%Y-%m-%d')
                            tempport.deltalastin = 0
                            tempport.deltalastout = 0
                # self.successful_switches.append(ipaddr)
                returnval = (True, ipaddr)
                with bz2.BZ2File(
                        os.path.join(self.subs.log_path, "activitycheck", "rawfiles","active", "{}-statcheck.bz2".format(ipaddr)),
                        'wb') as sfile:
                    pickle.dump(OldSwitchStatus, sfile)
                    sfile.close()

                with bz2.BZ2File(
                        os.path.join(self.subs.log_path, "activitycheck", "rawfiles","legacy", "{}-statcheck.bz2".format(ipaddr)),
                        'wb') as sfile:
                    pickle.dump(OldSwitchStatus, sfile)
                    sfile.close()



            except ValueError as err:
                print(err)
                # self.failure_switches.append(ipaddr)
                returnval = (False,ipaddr)
            except Exception as err: #currently a catch all to stop linux from having a conniption when reloading
                print("##### {} FILE ERROR:{} #####".format(ipaddr,err.args[0]))
                self.subs.custom_printer("debug", "## DBG - Error in Activity_Tracking ##")
                # self.failure_switches.append(ipaddr)
                returnval = (False, ipaddr)

            end = time.time()
            self.subs.verbose_printer("##### {} -  Processing Complete, time:{} seconds #####".format(ipaddr, int((end - start) * 100) / 100))

            return returnval
        except Exception as err: #catch all exception
            print("##### {} UNKNOWN ERROR:{} #####".format(ipaddr, err.args[0]))
            # self.failure_switches.append(ipaddr)
            end = time.time()
            self.subs.verbose_printer(
                "##### {} -  Processing aborted/failure, time:{} seconds #####".format(ipaddr, int((end - start) * 100) / 100))
            return (False,ipaddr)








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
