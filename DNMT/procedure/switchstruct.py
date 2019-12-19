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

    # def getPortById(self,Id):
    #     return next((x for x in self.switches if x.getPortById(Id) is not None), None)
        #return self.switches.getPortById(Id)


class SwitchStruct:
    def __init__(self, switchNum):
        # initialize values

        self.switchnumber = int(switchNum)
        self.model = None
        self.serialnumber = None
        #self.uptime = None
        self.modules = []


    def addModule(self,portInfo):
        self.modules.append(ModuleStruct(portInfo))

    def getModule(self, portNum):
        return next((x for x in self.modules if x.modulenumber == portNum), None)

    def getModules(self): #uneccessary for a get function as we can directly access
        return self.modules


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

    def getPorts(self):  # uneccessary for a get function as we can directly access
        return self.ports


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





