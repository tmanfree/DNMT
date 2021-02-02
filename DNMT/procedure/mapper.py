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
import socket

import zipfile #imports for summary filescompression imports






#3rd party imports
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import netmiko
from pathos.multiprocessing import ProcessingPool as Pool

#local subroutine import
from DNMT.procedure.subroutines import SubRoutines
from DNMT.procedure.switchstruct import StackStruct

#For Graphing (requires graphviz installed on machine)
from graphviz import Graph


class Mapper:
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
        self.visitedNeighbours = []
        self.pendingNeighbours = []
        self.coreFacingNodes = []
        self.coreNodes=[]
        self.graphObject = Graph(format='png')


    def iterate(self):
        # os.environ["PATH"] += os.pathsep + "C:\\Program Files\\Graphviz\\bin\\"  # required for testing on PC
        iplist = []

        total_start = time.time()

        try:
            file = open(os.path.join(self.cmdargs.filename), "r")
            self.subs.verbose_printer("##### file opened:{} #####".format(file))

            for ip in file:
                iplist.append(ip.rstrip())
            file.close()

            for ipaddr in iplist:

                neigh_ip = socket.gethostbyname(ipaddr)
                if neigh_ip not in self.pendingNeighbours and neigh_ip not in self.visitedNeighbours:
                    self.pendingNeighbours.append(ipaddr)

                while len(self.pendingNeighbours) > 0:
                    self.checkNeighbours(self.pendingNeighbours.pop())

            graphFileName = "Graph-{}".format(datetime.datetime.now().strftime('%Y-%m-%d-%H%M'))
            self.graphObject.render(graphFileName, view=False, cleanup=True)

            try:
                ##################
                if 'email' in self.cmdargs and self.cmdargs.email is not None:
                    msg_subject = "updated activitycheck - {}".format(datetime.date.today().strftime('%Y-%m-%d'))

                    # body = "Testing email"
                    body = "Processing completed in {} seconds\n".format(int((time.time() - total_start) * 100) / 100)
                    body += "{} switch state files SUCCESSFULLY updated\n".format(len(self.successful_switches))
                    body += "{} switch state files FAILED to update\n".format(len(self.failure_switches))
                    body += "\n--------------------------------------------------------------------------------------\n\n"

                    if len(self.successful_switches) > 0:
                        body += "--- List of switch statuses SUCCESSFULLY updated ---\n"
                        for entry in self.successful_switches:
                            body += "{}\n".format(entry)
                    if len(self.failure_switches) > 0:
                        body += "--- List of switch statuses that FAILED to update ---\n"
                        for entry in self.failure_switches:
                            body += "{}\n".format(entry)
                    self.subs.email_with_attachment(msg_subject, self.cmdargs.email, body,
                                                    "{}.png".format(graphFileName))
                else:
                    print(self.graphObject.source)
                    #######################
            except Exception as err:
                print(err)
            if 'remove' in self.cmdargs and self.cmdargs.remove:
                if os.path.exists("{}.png".format(graphFileName)):
                    os.remove("{}.png".format(graphFileName))
                else:
                    print("The file does not exist")

        except FileNotFoundError:
            print("##### ERROR iplist files not found #####")
        except Exception as err:
            print ("##### ERROR with processing:{} #####".format(err))





    def checkNeighbours(self, ipaddr):
        self.subs.custom_printer("debug","##DEBUG - Processing {} ##".format(ipaddr))
        node_ip = socket.gethostbyname(ipaddr)
        try:
            node_name = socket.gethostbyaddr(ipaddr)
        except Exception as err: # if failure in resolving hostname, make it the passed ip
            print("### ERROR on {} ### {}".format(ipaddr,err,))
            node_name = ipaddr

        vendor = self.subs.snmp_get_vendor_string(node_ip)
        for port in self.subs.snmp_get_neighbour_bulk(node_ip, vendor):
            self.subs.custom_printer("debug", "##DEBUG - {} - port {} ##".format(node_ip,port))
            if port['Category'] in [6, 9]:  # 6 for Cisco, 9 for Dell
                if "net.ualberta.ca" in port['Value']:
                    try:
                        neigh_node_name = socket.gethostbyaddr(port['Value'])
                    except socket.gaierror as err:
                        print("### ERROR on {} ### {} for {}".format(ipaddr,err,port['Value']))
                        neigh_node_name = [port['Value']] # if it cannot resolve the name, just apply the name to the graph
                    self.graphObject.edge(node_name[0],neigh_node_name[0]) # will add an edge by name
                if "orenet.ualberta.ca" in port['Value']: #if core just add the name for later creation of a tree, don't search the core device
                    if node_ip not in self.coreFacingNodes:
                        self.coreFacingNodes.append(node_ip)
                    if port['Value'] not in self.coreNodes:
                        self.coreNodes.append(port['Value'])
                elif "net.ualberta.ca" in port['Value']:
                    try:
                        neigh_ip = socket.gethostbyname(port['Value'])
                        if (neigh_ip not in self.visitedNeighbours and neigh_ip not in self.pendingNeighbours):
                            self.pendingNeighbours.append(neigh_ip)
                    except socket.gaierror as err:
                        print("### ERROR on {} ### {} for {}".format(ipaddr,err,port['Value']))
                    except Exception as err:
                        print(err)

        self.visitedNeighbours.append(node_ip)
        self.successful_switches.append(node_ip)

