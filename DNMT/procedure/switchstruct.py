#!/usr/bin/env python3

import random, re, socket,time,sys
import subprocess,platform
import netmiko
from pysnmp.hlapi import *

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902



class StackStruct:
    #External Variables/Methods
    CSVHeader = "IP,Vendor,Hostname,System Uptime,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE,Neighbour name,Neighbour port,Neighbour type, Neighbour IP, Status (1=Up),DataVlan,DataVlan name,VoiceVlan,Mode (1=Trunk),IntID,PsViolations,InputErrors,OutputErrors,InputCounters,OutputCounters,LastTimeUpdated,DeltaInputCounters,DeltaOutputCounters,HistoricalInputErrors,HistoricalOutputErrors,HistoricalInputCounters,HistoricalOutputCounters"

    def getHeader(flags):
        if 'xecutive' in flags and eval("flags.xecutive"):
            return "IP,Vendor,Hostname,System Uptime,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE draw (1=Yes),Status (1=Up),DataVlan,DataVlan name,VoiceVlan,Mode (1=Trunk),PsViolations,InputErrors,OutputErrors,InputCounters,OutputCounters,LastTimeUpdated,DeltaInputCounters,DeltaOutputCounters\n"
        else:
            return "{}\n".format(StackStruct.CSVHeader)

    #Finish External Methods

    def __init__(self,ipaddr,vendor):
        # initialize values
        self.ip = ipaddr
        self.vendor = vendor
        self.hostname = None
        self.uptime = None
        self.switches = []
        self.vlanList = []
        # self.CSVHeader = "IP,Vendor,Hostname,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE,Neighbour name,Neighbour port,Neighbour Info,Status (1=Up),DataVlan,VoiceVlan,Mode (1=Trunk),IntID,PsViolations,InputErrors,OutputErrors,InputCounters,OutputCounters,LastTimeUpdated,DeltaInputCounters,DeltaOutputCounters"



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

    def getPortByDesc_Exact(self,PortDesc):
        return [port for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if PortDesc == port.description]

    def getPortByDesc_Exact_Insensitive(self,PortDesc):
        return [port for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if
                PortDesc.lower() == port.description.lower()]

    def getPortByDesc_Partial(self,PortDesc):
        return [port for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if PortDesc in port.description]

    def getPortByDesc_Partial_Insensitive(self,PortDesc):
        return [port for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if PortDesc.lower() in port.description.lower()]


    def getPortById(self,Id):
        return next((port for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if port.intID == Id),
                    None)

    def getSwitchByPortId(self, Id):
        return next((Sw for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if port.intID == Id),
                    None)

    def printStack(self):
        print("IP:{}\nVendor:{}\nHosntame:{},\nSystem Uptime:{}".format(self.ip,self.vendor,self.hostname, self.uptime))
        for switch in self.switches:
            switch.printSwitch()

    def printSingleLine(self):
        print(StackStruct.CSVHeader)
        for switch in self.switches:
            switch.printSingleLine(self.ip, self.vendor, self.hostname, "\"{}\"".format(str(self.uptime).replace(',',' ')))

    # def appendSingleLine(self):
    #     totalString = ""
    #     for switch in self.switches:
    #         totalString += switch.appendSingleLine(self.ip,self.vendor, self.hostname)
    #     return totalString
    #
    # def appendSingleLineExec(self):
    #     totalString = ""
    #     # if self.vlanList
    #     for switch in self.switches:
    #         totalString += switch.appendSingleLineExec((self.ip,self.vendor, self.hostname))
    #     return totalString

    def appendSingleLineCustom(self,**kwargs):
        totalString = ""

        for varname in ['uptime','hostname']: #checker to avoid newly added attributes being missing
            if not hasattr(self,varname):
                setattr(self,varname,None)

        for switch in self.switches:
            totalString += switch.appendSingleLineCustom((self.ip,self.vendor, self.hostname, "\"{}\"".format(str(self.uptime).replace(',',' '))),**kwargs)
        return totalString

    def exportCSV(self,filename):
        with open(filename, 'w', encoding='utf-8') as filePointer:

            print(StackStruct.CSVHeader,file=filePointer)

            for switch in self.switches:
                switch.exportCSV(self.ip,self.vendor, self.hostname, "\"{}\"".format(str(self.uptime).replace(',',' ')),filePointer)

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

    # def appendSingleLine(self, ip,vendor, hostname):
    #     totalString =""
    #     for module in self.modules:
    #         totalString += module.appendSingleLine((ip,vendor,hostname, self.switchnumber, self.model, self.serialnumber, self.version))
    #     return totalString
    #
    # def appendSingleLineExec(self, passedTup):
    #     totalString =""
    #     for module in self.modules:
    #         totalString += module.appendSingleLineExec(passedTup+(self.switchnumber, self.model, self.serialnumber, self.version))
    #     return totalString

    def appendSingleLineCustom(self, passedTup, **kwargs):
        totalString =""
        for module in self.modules:
            totalString += module.appendSingleLineCustom(passedTup+(self.switchnumber, self.model, self.serialnumber, self.version),**kwargs)
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

    # def appendSingleLine(self,passedTup):
    #     totalString = ""
    #     for port in self.ports:
    #         totalString += port.appendSingleLine(passedTup+(self.modulenumber,))
    #     return totalString
    #
    # def appendSingleLineExec(self,passedTup):
    #     totalString = ""
    #     for port in self.ports:
    #         totalString += port.appendSingleLineExec(passedTup+(self.modulenumber,))
    #     return totalString

    def appendSingleLineCustom(self, passedTup, **kwargs):
        totalString = ""
        for port in self.ports:
            totalString += port.appendSingleLineCustom(passedTup+(self.modulenumber,),**kwargs)
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
        self.cdpip = None
        self.status = None
        self.datavlan = None
        self.datavlanname = None
        self.voicevlan = None
        self.voicevlanname = None
        self.portmode = None #access/trunk
        self.intID = int(portNum)
        self.psviolations = None
        #self.nummacaddresses = None
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
                    self.psviolations != compareport.psviolations or
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

    # def checkForVars(self,varList):
    #    list_of_existing_vars = [a for a in dir(self) if not a.startswith('__')]


    def appendSingleLineCustom(self,passedTup,**kwargs):
        if "remove_empty_filter" in kwargs: #currently works on comma seperated filters, recursively call a function that will return  on all after a split if multiples?
            filterList = kwargs['remove_empty_filter'].split(',')
            for removalFilter in filterList:
                if hasattr(self,removalFilter): # check for existence of field
                    if eval("self.{} == 0 or self.{} == None".format(removalFilter,removalFilter)): #check if field is empty
                        return ""
                else: #return blank if the field to filter out does not exist
                    return ""
        if("executive_mode" in kwargs and kwargs['executive_mode']):
            poePrinting = 0
            dataVlanName = ""
            voiceVlanName = ""

            if self.poe is not None and self.poe > 0:
                poePrinting = 1  # to act as a binary poe or no
            # dataVlanName = [vlanEntry['Name'] for vlanEntry in vlanList if 'ID' in vlanEntry and vlanEntry["ID"  == self.datavlan]]

            while True:
                try:
                    return "{},{},{},\"{}\",{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{}\n".format(
                        str(passedTup).translate({ord(i): None for i in '()\''}),
                        self.portnumber, self.portname, self.description, poePrinting,
                        self.status, self.datavlan, self.datavlanname, self.voicevlan,
                        self.portmode, self.psviolations, self.inputerrors, self.outputerrors,
                        self.inputcounters, self.outputcounters,
                        self.lastupdate, self.deltalastin, self.deltalastout)
                except AttributeError as errmsg:
                    # test = re.findall(r'^\*\s+(\d)', errmsg,re.MULTILINE)
                    regsearch = re.findall(r"object has no attribute '(\S+)'$", errmsg.args[0], re.MULTILINE)
                    if len(regsearch) > 0:
                        exec("self." + regsearch[0] + "= None")
                    else:
                        raise Exception(
                            '##### ERROR - missing required Data to print: {} #####'.format(errmsg.args[0]))
        else:
            while True:
                try:
                    return "{},{},{},\"{}\",{},\"{}\",{},\"{}\",{}, {},{},{},{},{},{},{},{},{},{},{},{},{},{},\"{}\",\"{}\",\"{}\",\"{}\"\n".format(
                        str(passedTup).translate({ord(i): None for i in '()\''}),
                        self.portnumber, self.portname, self.description, self.poe,
                        self.cdpname, self.cdpport, self.cdptype, self.cdpip, self.status, self.datavlan,
                        self.datavlanname, self.voicevlan,
                        self.portmode, self.intID, self.psviolations,
                        self.inputerrors, self.outputerrors,
                        self.inputcounters, self.outputcounters,
                        self.lastupdate, self.deltalastin, self.deltalastout, self.historicalinputerrors,
                        self.historicaloutputerrors,
                        self.historicalinputcounters, self.historicaloutputcounters)
                except AttributeError as errmsg:
                    # test = re.findall(r'^\*\s+(\d)', errmsg,re.MULTILINE)
                    regsearch = re.findall(r"object has no attribute '(\S+)'$", errmsg.args[0], re.MULTILINE)
                    if len(regsearch) > 0:
                        exec("self." + regsearch[0] + "= None")
                    else:
                        raise Exception(
                            '##### ERROR - missing required Data to print: {} #####'.format(errmsg.args[0]))






    # def appendSingleLine (self,passedTup):
    #     while True:
    #         try:
    #             return "{},{},{},\"{}\",{},\"{}\",{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},{},{},\"{}\",\"{}\",\"{}\",\"{}\"\n".format(
    #                 str(passedTup).translate({ord(i): None for i in '()\''}),
    #                 self.portnumber, self.portname, self.description, self.poe,
    #                 self.cdpname, self.cdpport, self.cdptype, self.status, self.datavlan,
    #                 self.datavlanname,self.voicevlan,
    #                 self.portmode, self.intID, self.psviolations,
    #                 self.inputerrors, self.outputerrors,
    #                 self.inputcounters, self.outputcounters,
    #                 self.lastupdate, self.deltalastin, self.deltalastout,self.historicalinputerrors,self.historicaloutputerrors,
    #                 self.historicalinputcounters,self.historicaloutputcounters)
    #         except AttributeError as errmsg:
    #             # test = re.findall(r'^\*\s+(\d)', errmsg,re.MULTILINE)
    #             regsearch = re.findall(r"object has no attribute '(\S+)'$", errmsg.args[0], re.MULTILINE)
    #             if len(regsearch) > 0:
    #                 exec("self."+regsearch[0] + "= None")
    #             else:
    #                 raise Exception('##### ERROR - missing required Data to print: {} #####'.format(errmsg.args[0]))
    #
    # def appendSingleLineExec (self,passedTup):
    #     # self.checkForVars(["portnumber","portname","description",""])
    #     poePrinting = 0
    #     dataVlanName = ""
    #     voiceVlanName = ""
    #
    #     if self.poe is not None and self.poe > 0:
    #         poePrinting = 1 #to act as a binary poe or no
    #     # dataVlanName = [vlanEntry['Name'] for vlanEntry in vlanList if 'ID' in vlanEntry and vlanEntry["ID"  == self.datavlan]]
    #
    #     while True:
    #         try:
    #             return "{},{},{},\"{}\",{},{},{},\"{}\",{},{},{},{},{},{},{},{},{},{}\n".format(
    #                 str(passedTup).translate({ord(i): None for i in '()\''}),
    #                 self.portnumber, self.portname, self.description, poePrinting,
    #                 self.status, self.datavlan, self.datavlanname,self.voicevlan,
    #                 self.portmode,self.psviolations, self.inputerrors, self.outputerrors,
    #                 self.inputcounters, self.outputcounters,
    #                 self.lastupdate, self.deltalastin, self.deltalastout)
    #         except AttributeError as errmsg:
    #             # test = re.findall(r'^\*\s+(\d)', errmsg,re.MULTILINE)
    #             regsearch = re.findall(r"object has no attribute '(\S+)'$", errmsg.args[0], re.MULTILINE)
    #             if len(regsearch) > 0:
    #                 exec("self."+regsearch[0] + "= None")
    #             else:
    #                 raise Exception('##### ERROR - missing required Data to print: {} #####'.format(errmsg.args[0]))




    def printSingleLine(self,passedTup):
        print("{},{},{},\"{}\",{},\"{}\",{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(str(passedTup).translate({ord(i): None for i in '()\''}),
                                                        self.portnumber, self.portname, self.description, self.poe,
                                                        self.cdpname, self.cdpport, self.cdptype, self.cdpip, self.status,
                                                        self.datavlan, self.datavlanname, self.voicevlan,
                                                        self.portmode, self.intID, self.psviolations, self.inputerrors, self.outputerrors,
                                                              self.inputcounters, self.outputcounters,
                                                              self.lastupdate,self.deltalastin,self.deltalastout))
    def exportCSV(self,passedTup,filePointer):
        print("{},{},{},\"{}\",{},\"{}\",{},\"{}\",{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(str(passedTup).translate({ord(i): None for i in '()\''}),
                                                        self.portnumber, self.portname, self.description, self.poe,
                                                        self.cdpname, self.cdpport, self.cdptype, self.cdpip, self.status,
                                                        self.datavlan,self.datavlanname,self.voicevlan,
                                                        self.portmode, self.intID, self.psviolations, self.inputerrors, self.outputerrors,
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
        print("port CDP remote IP:{}".format(self.cdpip))
        print("port Status (1=up,2=down):{}".format(self.status))
        print("port DataVlan:{}".format(self.datavlan))
        print("port DataVlan Name:{}".format(self.datavlanname))
        print("port VoiceVlan:{}".format(self.voicevlan))
        print("port Mode:{}".format(self.portmode))
        print("port ID:{}".format(self.intID))
        print("port Port-Security Violations:{}".format(self.psviolations))
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





