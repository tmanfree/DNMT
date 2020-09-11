#!/usr/bin/env python3

import random, re, socket,time,sys
import subprocess,platform
import netmiko
from pysnmp.hlapi import *

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902



class StackStruct:
    def __init__(self,ipaddr,vendor):
        # initialize values
        self.ip = ipaddr
        self.vendor = vendor
        self.hostname = None
        self.switches = []
        self.CSVHeader = "IP,Vendor,Hostname,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE,Neighbour name,Neighbour port,Neighbour Info,Status (1=Up),DataVlan,VoiceVlan,Mode (1=Trunk),IntID,InputErrors,OutputErrors,InputCounters,OutputCounters,LastTimeUpdated,DeltaInputCounters,DeltaOutputCounters"

    def addSwitch(self,switchNum):
        self.switches.append(SwitchStruct(switchNum))

    def addExistingSwitch(self,switchCopy):
        self.switches.append(switchCopy)

    def getSwitch(self,switchNum):
        return next((x for x in self.switches if x.switchnumber == switchNum), None)

    def getSwitchBySerialNumber(self,serialNumber):
        return next((x for x in self.switches if x.serialnumber == serialNumber), None)

    def getSwitches(self):#uneccessary for a get function as we can directly access
        return self.switches

    def getPortByPortName(self,PortName):
        return next((port for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if port.portname == PortName),
                    None)

    def getPortById(self,Id):
        return next((port for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if port.intID == Id),
                    None)

    def getSwitchByPortId(self, Id):
        return next((Sw for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if port.intID == Id),
                    None)

    def printStack(self):
        print("IP:{}\nVendor:{}\nHosntame:{}".format(self.ip,self.vendor,self.hostname))
        for switch in self.switches:
            switch.printSwitch()

    def printSingleLine(self):
        print(self.CSVHeader)
        for switch in self.switches:
            switch.printSingleLine(self.ip, self.vendor, self.hostname)

    def appendSingleLine(self):
        totalString = ""
        for switch in self.switches:
            totalString += switch.appendSingleLine(self.ip,self.vendor, self.hostname)
        return totalString

    def exportCSV(self,filename):
        with open(filename, 'w', encoding='utf-8') as filePointer:

            print(self.CSVHeader,file=filePointer)

            for switch in self.switches:
                switch.exportCSV(self.ip,self.vendor, self.hostname,filePointer)

    # def csvStack(self):
    #     with open("test.csv", 'w', encoding='utf-8') as f:
    #         print("MAC,Switch_IP,Port,Info", file=f)
    #         [print("%s" % (entry['csv']), file=f) for entry in self.log_array]



class SwitchStruct:
    def __init__(self, switchNum):
        # initialize values

        self.switchnumber = int(switchNum)
        self.model = None
        self.id = None
        self.version = None
        self.serialnumber = None
        #self.uptime = None
        self.modules = []


    def addModule(self,portInfo):
        self.modules.append(ModuleStruct(portInfo))

    def getModule(self, portNum):
        return next((x for x in self.modules if x.modulenumber == portNum), None)

    def printSwitch(self):
        for module in self.modules:
            print("Switch #:{}\nModel:{}\nSerial #:{}\nVersion:{}".format(self.switchnumber, self.model,
                                                                          self.serialnumber,self.version))
            module.printModule()

    def printSingleLine(self,ip,vendor, hostname):
        for module in self.modules:
            #print("{},{},{}".format(self.switchnumber,self.model,self.serialnumber), end = ",")
            module.printSingleLine((ip,vendor,hostname,self.switchnumber,self.model,self.serialnumber,self.version))

    def appendSingleLine(self, ip,vendor, hostname):
        totalString =""
        for module in self.modules:
            totalString += module.appendSingleLine((ip,vendor,hostname, self.switchnumber, self.model, self.serialnumber, self.version))
        return totalString

    def exportCSV(self,ip,vendor, hostname, filePointer):
        for module in self.modules:
            module.exportCSV((ip,vendor,hostname,self.switchnumber,self.model,self.serialnumber,self.version),filePointer)


class ModuleStruct:
    def __init__(self, moduleNum):

        self.modulenumber = int(moduleNum)
        self.ports = []

    def addPort(self, portInfo):
        self.ports.append(PortStruct(portInfo))

    def getPort(self, portNum):
        return next((x for x in self.ports if x.portnumber == portNum), None)

    def getPortByID(self, portID):
        return next((x for x in self.ports if x.portID == portID), None)

    def printModule(self):
        print("Module #:{}".format(self.modulenumber))
        for port in self.ports:
            port.printPort()

    def printSingleLine(self,passedTup):
        for port in self.ports:
            #print("{}".format(self.modulenumber), end = ",")
            port.printSingleLine(passedTup+(self.modulenumber,))

    def appendSingleLine(self,passedTup):
        totalString = ""
        for port in self.ports:
            totalString += port.appendSingleLine(passedTup+(self.modulenumber,))
        return totalString

    def exportCSV(self, passedTup, filePointer):
        for port in self.ports:
            port.exportCSV(passedTup+(self.modulenumber,),filePointer)



class PortStruct:
    def __init__(self, portNum):
        # initialize values
        self.portnumber = None
        self.portname = None
        self.description = None
        self.poe = None
        self.cdpname = None
        self.cdpport = None
        self.cdptype = None
        self.status = None
        self.datavlan = None
        self.voicevlan = None
        self.portmode = None #access/trunk
        self.intID = int(portNum)
        self.inputerrors = None
        self.outputerrors = None
        self.inputcounters = None
        self.outputcounters = None

        self.maxhistoricalentries = 60 #this could be modified to keep longer or shorter records on a port by port basis
        self.historicalinputerrors = []
        self.historicaloutputerrors = []
        self.historicalinputcounters = []
        self.historicaloutputcounters = []

        self.lastupdate = None #specific to activity tracking
        self.deltalastin = None #specific to activity tracking
        self.deltalastout = None #specific to activity tracking

    def checkCounterExistance(self):
        if len(self.inputcounters) == 0:
            self.inputcounters
            self.outputerrors[len(self.outputerrors)]

    def activityChanged(self,compareport):
        try:
            if (self.cdpname != compareport.cdpname or
                    self.description != compareport.description or
                    self.cdpport != compareport.cdpport or
                    self.cdptype != compareport.cdptype or
                    self.datavlan != compareport.datavlan or
                    self.voicevlan != compareport.voicevlan or
                    self.poe != compareport.poe or
                    self.status != compareport.status or
                    self.portmode != compareport.portmode or
                    self.inputerrors != compareport.inputerrors or
                    self.outputerrors != compareport.outputerrors or
                    self.inputcounters != compareport.inputcounters or
                    self.outputcounters != compareport.outputcounters):
                return True
            else:
                return False
        except AttributeError as err:  # currently a catch all to stop linux from having a conniption when reloading
            # print("#####  Attribute not found ERROR:{} #####".format(err.args[0]))
            return True # return true to over write any ports that don't have the required new fields. Ignore old removed ones

    def appendSingleLine (self,passedTup):
        return "{},{},{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},{},{},\"{}\",\"{}\",\"{}\",\"{}\"\n".format(
            str(passedTup).translate({ord(i): None for i in '()\''}),
            self.portnumber, self.portname, self.description, self.poe,
            self.cdpname, self.cdpport, self.cdptype, self.status, self.datavlan, self.voicevlan,
            self.portmode, self.intID, self.inputerrors, self.outputerrors,
            self.inputcounters, self.outputcounters,
            self.lastupdate, self.deltalastin, self.deltalastout,self.historicalinputerrors,self.historicaloutputerrors,
            self.historicalinputcounters,self.historicaloutputcounters)

    def printSingleLine(self,passedTup):
        print("{},{},{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(str(passedTup).translate({ord(i): None for i in '()\''}),
                                                        self.portnumber, self.portname, self.description, self.poe,
                                                        self.cdpname, self.cdpport, self.cdptype, self.status, self.datavlan, self.voicevlan,
                                                        self.portmode, self.intID, self.inputerrors, self.outputerrors,
                                                              self.inputcounters, self.outputcounters,
                                                              self.lastupdate,self.deltalastin,self.deltalastout))
    def exportCSV(self,passedTup,filePointer):
        print("{},{},{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(str(passedTup).translate({ord(i): None for i in '()\''}),
                                                        self.portnumber, self.portname, self.description, self.poe,
                                                        self.cdpname, self.cdpport, self.cdptype, self.status, self.datavlan, self.voicevlan,
                                                        self.portmode, self.intID, self.inputerrors, self.outputerrors,
                                                              self.inputcounters, self.outputcounters,
                                                              self.lastupdate,self.deltalastin,self.deltalastout),
              file=filePointer)




    def printPort(self):
        print("port {}".format(self.portnumber))
        print("port name:{}".format(self.portname))
        print("port description:{}".format(self.description))
        print("port POE:{}".format(self.poe))
        print("port CDP name:{}".format(self.cdpname))
        print("port CDP remote port:{}".format(self.cdpport))
        print("port CDP device type:{}".format(self.cdptype))
        print("port Status (1=up,2=down):{}".format(self.status))
        print("port DataVlan:{}".format(self.datavlan))
        print("port VoiceVlan:{}".format(self.voicevlan))
        print("port Mode:{}".format(self.portmode))
        print("port ID:{}".format(self.intID))
        print("port Input Errors:{}".format(self.inputerrors))
        print("port Output Errors:{}".format(self.outputerrors))
        print("port Input Counters:{}".format(self.inputcounters))
        print("port Output Counters:{}".format(self.outputcounters))
        print("Last Update time:{}".format(self.lastupdate))
        print("Delta last input Counters:{}".format(self.deltalastin))
        print("Delta last output Counters:{}".format(self.deltalastout))
        print("Max Historical Entries:{}".format(self.maxhistoricalentries))
        print("Historical Input Errors:{}".format(self.historicalinputerrors))
        print("Historical Output Errors:{}".format(self.historicaloutputerrors))
        print("Historical Input Counters:{}".format(self.historicalinputcounters))
        print("Historical Output Counters:{}".format(self.historicaloutputcounters))

    #Setters, in retrospect these variables can be accessed directly...
    def setPoE(self,PoE):
        self.poe = PoE

    # def setCdp(self,CDP):
    #     self.cdp = CDP

    def setName(self, Name):
        self.portname = Name

    def setDescription(self, Desc):
        self.description = Desc

    def setStatus(self,Status):
        self.status = Status

    def setDataVlan(self,Data):
        self.datavlan = Data

    def setVoiceVlan(self,Voice):
        self.voicevlan = Voice

    def setMode(self,Mode):
        self.portmode = Mode

    def setIntID(self,ID):
        self.intID = ID





