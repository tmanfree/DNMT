#!/usr/bin/env python3
#class dedicated to archival functions for dnmt data

import re
import sys
import subprocess,platform,os,time,datetime,zipfile
import difflib
import pickle
import collections
# import pysvn
# import git


#3rd party imports



#local subroutine import
from DNMT.procedure.subroutines import SubRoutines




class Archivist:
    def __init__(self, cmdargs, config):
        # initialize values
        self.log_array = []
        self.cmdargs = cmdargs
        self.config = config
        self.subs = SubRoutines(cmdargs, config)
        self.config.logpath = os.path.join(os.path.expanduser(self.config.logpath), "logs", "UpgradeCheck",
                                           datetime.date.today().strftime('%Y%m%d'))

    def basic_maintenance(self,maxfiles):
        #
        self.subs.verbose_printer("##### Cleaning up backup files #####")

        #Remove oldest files (listed first on windows
        filelist = os.listdir(os.path.join(self.subs.log_path, "activitycheck", "backups"))
        if len(filelist) > 0 and len(filelist) > maxfiles:
            # self.subs.verbose_printer("##### unsorted list:{} #####".format(filelist))
            sortedfilelist = sorted(filelist)
            # self.subs.verbose_printer("##### sorted list:{} #####".format(testlist))
            filestoremove = sortedfilelist[0:(len(filelist)-maxfiles)]
            self.subs.custom_printer("verbose", "total files:{}\nremoving files:{}".format(len(filelist),len(filestoremove)))
            for file in filestoremove:
                if file.endswith("-SwitchStatus.Backup.zip"):
                    # process
                    try:
                        self.subs.verbose_printer("##### File to remove:{} #####".format(file))
                        if 'check' in self.cmdargs and self.cmdargs.check is True :
                            self.subs.custom_printer("debug", "## DBG - testing, would have removed {} ##".format(file))
                        else:
                            self.subs.custom_printer("debug", "## Removing file {} ##".format(file))
                            os.remove(os.path.join(self.subs.log_path, "activitycheck", "backups", file))

                    except Exception as err:  # currently a catch all to stop linux from having a conniption when reloading
                        print("FILE ERROR {}:{}".format(file, err.args[0]))

        else:
            self.subs.verbose_printer("total files:{} are less than max value:{}".format(len(filelist), maxfiles))

    def basic_archival(self):
        try:
            working_folder = os.path.join(self.subs.log_path, "activitycheck", "rawfiles", "legacy")


            zipfile_name = os.path.join(self.subs.log_path, "activitycheck", "backups",
                                        "{}-SwitchStatus.Backup.zip".format(
                                            datetime.datetime.now().strftime("%Y%m%d%H%M")))
            files = os.listdir(working_folder)
            files_py = files

            # zipfile_name = "SwitchStatus Backup {}.zip".format(datetime.datetime.now().strftime("%Y%m%d%H%M"))

            #check for existance of the directory (if a first run)
            if not os.path.exists(os.path.join(self.subs.log_path, "activitycheck", "backups")):
                self.subs.custom_printer("debug", "## DBG - Creating activitycheck/backups directory ##")
                os.makedirs(os.path.join(self.subs.log_path, "activitycheck", "backups"))

            ZipFile = zipfile.ZipFile(zipfile_name, "a")

            self.subs.custom_printer("debug", "## DBG - adding files to backup zipfile:{} ##".format(zipfile_name))
            for a in files_py:
                full_file_path = os.path.join(working_folder,a)
                # ZipFile.write(full_file_path, compress_type=zipfile.ZIP_DEFLATED)
                ZipFile.write(full_file_path,a, compress_type=zipfile.ZIP_DEFLATED)
            ZipFile.close()


            self.subs.custom_printer("debug", "## DBG - zipfile backup created ##")

            if 'email' in self.cmdargs and self.cmdargs.email is not None:
                msg_subject = "SwitchStatus Backup {}".format(datetime.date.today().strftime('%Y-%m-%d'))
                body = "Attached is the Legacy Backup files"
                self.subs.custom_printer("debug", "## DBG - sending email ##")
                self.subs.email_with_attachment(msg_subject, self.cmdargs.email, body, zipfile_name)

            if 'remove' in self.cmdargs and self.cmdargs.remove:
                if os.path.exists("{}".format(zipfile_name)):
                    os.remove("{}".format(zipfile_name))
                    self.subs.custom_printer("debug", "## DBG - zipfile {} removed ##".format(zipfile_name))
                else:
                    print("The file does not exist")

            if 'maintenance' in self.cmdargs and self.cmdargs.maintenance is not None:
                try:
                    self.basic_maintenance(int(self.cmdargs.maintenance))
                except ValueError:
                    self.subs.custom_printer("debug", "## DBG - maintenance({}) is not a number. maintenance not performed ##".format(self.cmdargs.maintenance))

        except Exception as err:
            print(err)


    def test(self):
        try:
            # write a file foo.txt
            pass
            # repo = Repo(self.rorepo.working_tree_dir)
            # assert not repo.bare

        except Exception as err:
            print(err)