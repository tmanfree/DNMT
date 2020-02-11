#!/usr/bin/env python3

import random, re, socket,time,sys
import subprocess,platform
import netmiko
from pysnmp.hlapi import *

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902



class StackStruct:
    def __init__(self,ipaddr):
        # initialize values
        self.ip = ipaddr
        self.switches = []

    def addSwitch(self,switchNum):
        self.switches.append(SwitchStruct(switchNum))

    def getSwitch(self,switchNum):
        return next((x for x in self.switches if x.switchnumber == switchNum), None)

    def getSwitches(self):#uneccessary for a get function as we can directly access
        return self.switches

    def getPortById(self,Id):
        return next((port for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if port.intID == Id),
                    None)

    def getSwitchByPortId(self, Id):
        return next((Sw for Sw in self.switches for Mod in Sw.modules for port in Mod.ports if port.intID == Id),
                    None)

    def printStack(self):
        print("IP:{}".format(self.ip))
        for switch in self.switches:
            switch.printSwitch()

    def printSingleLine(self):
        print("IP,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE,CDP,Status,DataVlan,VoiceVlan,Mode,IntID,InputErrors,OutputErrors")
        for switch in self.switches:
            switch.printSingleLine(self.ip)

    def exportCSV(self,filename):
        with open(filename, 'w', encoding='utf-8') as filePointer:

            print(
                "IP,SwitchNum,Model,Serial,SoftwareVer,ModuleNum,PortNum,PortName,PortDesc,PoE,CDP,Status,DataVlan,VoiceVlan,Mode,IntID,InputErrors,OutputErrors",
                file=filePointer)

            for switch in self.switches:
                switch.exportCSV(self.ip,filePointer)

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

    def printSingleLine(self,ip):
        for module in self.modules:
            #print("{},{},{}".format(self.switchnumber,self.model,self.serialnumber), end = ",")
            module.printSingleLine((ip,self.switchnumber,self.model,self.serialnumber,self.version))

    def exportCSV(self,ip,filePointer):
        for module in self.modules:
            module.exportCSV((ip,self.switchnumber,self.model,self.serialnumber,self.version),filePointer)


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

    def exportCSV(self, passedTup, filePointer):
        for port in self.ports:
            port.exportCSV(passedTup+(self.modulenumber,),filePointer)



class PortStruct:
    def __init__(self, portNum):
        # initialize values
        self.portnumber = int(portNum)
        self.portname = None
        self.description = None
        self.poe = None
        self.cdp = None
        self.status = None
        self.datavlan = None
        self.voicevlan = None
        self.portmode = None #access/trunk
        self.intID = None
        self.inputerrors = None
        self.outputerrors = None

    def printSingleLine(self,passedTup):
        print("{},{},{},{},{},{},{},{},{},{},{},{},{}".format(str(passedTup).translate({ord(i): None for i in '()\''}),
                                                        self.portnumber, self.portname, self.description, self.poe,
                                                        self.cdp, self.status, self.datavlan, self.voicevlan,
                                                        self.portmode, self.intID, self.inputerrors, self.outputerrors))
    def exportCSV(self,passedTup,filePointer):
        print("{},{},{},{},{},{},{},{},{},{},{},{},{}".format(str(passedTup).translate({ord(i): None for i in '()\''}),
                                                        self.portnumber, self.portname, self.description, self.poe,
                                                        self.cdp, self.status, self.datavlan, self.voicevlan,
                                                        self.portmode, self.intID, self.inputerrors, self.outputerrors),
              file=filePointer)



    def printPort(self):
        print("port {}".format(self.portnumber))
        print("port name:{}".format(self.portname))
        print("port description:{}".format(self.description))
        print("port POE:{}".format(self.poe))
        print("port CDP:{}".format(self.cdp))
        print("port Status (1=up,2=down):{}".format(self.status))
        print("port DataVlan:{}".format(self.datavlan))
        print("port VoiceVlan:{}".format(self.voicevlan))
        print("port Mode:{}".format(self.portmode))
        print("port ID:{}".format(self.intID))
        print("port Input Errors:{}".format(self.inputerrors))
        print("port Output Errors:{}".format(self.outputerrors))

    #Setters, in retrospect these variables can be accessed directly...
    def setPoE(self,PoE):
        self.poe = PoE

    def setCdp(self,CDP):
        self.cdp = CDP

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





