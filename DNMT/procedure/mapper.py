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
        self.mappedEdges=[]
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
                        body += "--- List of switch statuses that FAILED to update or found no neighbours ---\n"
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
        #TODO use hostname for the name rather than resolving it?
        self.subs.custom_printer("debug","##DEBUG - Processing {} ##".format(ipaddr))

        try:
            node_name = socket.gethostbyaddr(ipaddr)
        except Exception as err: # if failure in resolving hostname, make it the passed ip
            print("### ERROR on {} ### {}".format(ipaddr,err,))
            node_name = [ipaddr,"",[ipaddr]]

        # test = self.subs.snmp_get_uptime(ipaddr)



        vendor = self.subs.snmp_get_vendor_string(ipaddr)

        #TODO combine get_neighbour results to have type & ip in the same entry for filtering
        bulkCDPList = self.subs.snmp_get_neighbour_bulk(ipaddr, vendor)
        if len(bulkCDPList) > 0:
            formattedCDPList = []
            for entry in bulkCDPList:
                if not any(d['Id'] == entry['Id'] for d in formattedCDPList):
                    formattedCDPList.append({"Id":entry["Id"]})
                for d in formattedCDPList:
                    if d['Id'] == entry['Id']:
                        d[entry['Category']] = entry['Value']



            for port in formattedCDPList:
                self.subs.custom_printer("debug", "##DEBUG - {} - port {} ##".format(ipaddr,port))
                if 'IP' in port.keys() and (not any(x in port['Type'] for x in ['Phone','AIR','VG','ATA'])):  # ignore phones,APs,VGs
                    try:
                        neigh_node_name = socket.gethostbyaddr(port['IP'])
                    except Exception as err:
                        print("### ERROR on {} ### {} for {}".format(ipaddr, err, port['IP']))
                        neigh_node_name = [port['Name'],"",[port['IP']]]  # if the host is not found



                    if any(x in port['Name'].lower() for x in
                           ['-ba-', '-ef-', '-ds-', '-cs-']) and "orenet.ualberta.ca" in port['Name']:
                        neigh_node_name[2][0] = port[
                            'Name']  # assign the IP to be the core hostname for checking with mapped edges

                    # if "net.ualberta.ca" in neigh_node_name[0] and all(x not in self.mappedEdges for x in [(node_name[2][0],neigh_node_name[2][0]), (neigh_node_name[2][0],node_name[2][0])]):
                    if all(x not in self.mappedEdges for x in[(node_name[2][0], neigh_node_name[2][0]),(neigh_node_name[2][0], node_name[2][0])]): #map all edges (turn off other types like linux?)

                        if any(x in port['Name'].lower() for x in ['-ba-','-ef-','-ds-','-cs-']) and "orenet.ualberta.ca" in port['Name']:
                            self.graphObject.edge("{}({})".format(node_name[0], node_name[2][0]),"{}".format(neigh_node_name[2][0]))  # will add a core edge
                        else:
                            self.graphObject.edge("{}({})".format(node_name[0],node_name[2][0]),"{}({})".format(neigh_node_name[0],neigh_node_name[2][0])) # will add an edge by name
                            if (port["IP"] not in self.visitedNeighbours and port["IP"] not in self.pendingNeighbours):
                                self.pendingNeighbours.append(port["IP"])

                        self.mappedEdges.append((node_name[2][0],neigh_node_name[2][0]))

                        # if "orenet.ualberta.ca" not in neigh_node_name and "orenet.ualberta.ca" not in port['Name']: #avoid going into core devices
                        #     if (port["IP"] not in self.visitedNeighbours and port["IP"] not in self.pendingNeighbours):
                        #         self.pendingNeighbours.append(port["IP"])

            self.successful_switches.append(ipaddr)
        else:
            self.failure_switches.append(ipaddr)

        self.visitedNeighbours.append(ipaddr)

