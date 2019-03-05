# Direct Network Management Tool (DNMT)

The Direct Network Management Tool *(DNMT)* is intended to house various functions that
require directly accessing switches through either SSH or SNMP.

DNMT can operate in direct or interactive mode. In direct, it will execute a 
single operation/function. In interactive mode it will show a prompt that displays
the various commands available. After using each command, the prompt will reappear.
 
 A config file (config.text) is required to get user information (username/pass/snmp/etc)

Current functionality:

* **MAC Search** - *dnmt.py direct MACSearch  -m MAC START_IP* . Based on the previous "Lefty" program,
 this is currently operational
in interactive or direct mode.
* **Hostname Updater** - *dnmt.py direct MACSearch IP MAC* . This will compare switch hostnames
with dns hostnames, updating the switch hostname if they are different.

## Requirements

* Python 3.5
* Python packages listed in setup.py
* a config.text file where you will run the command with the following information in it:
    * [SWITCHCRED]
    * username=*USERNAME*
    * password=*PASSWORD*
    * enable=*ENABLEPASS*
    * [SNMP]
    * ro=*SNMPV2ROSTRING*
    * rw=*SNMPV2RWSTRING*
    * [PATH]
    * logpath=*~*
    


## Detailed function breakdowns

### MAC Search

**Description**: This function can operate in either batch or single mode. Both require
an IP address to begin searching at

**Input Required:** 
* Batch mode
    * *-b FILENAME:* Supply the function with a file (*FILENAME*) that has multiple mac addresses    
* Single mode     
    * *-m MAC:* Supply a single mac address (*MAC*) to find 
    
**Optional Flags:**
* *-v*: verbose mode. Prints more output to the screen
* *-c FILENAME*: csv output to *FILENAME*. 
    
Example commands:

**dnmt direct MACSearch -m *AAAA.BBBB.CCCC* *1.1.1.1***

This command will search for MAC address *AAAA.BBBB.CCCC* starting from IP address 1.1.1.1

**dnmt direct MACSearch -b *macfile.txt* *1.1.1.1* -c *output.csv***

This command will search for all MAC addresses listed in *macfile.txt* 
 starting from IP address 1.1.1.1 and store results in *output.csv*

### Hostname Updater

**Description**: This function will take a list of ip addresses from a file and
compare their hostnames in DNS to their switch hostname. if the check flag is not set,
it will then update the switch hostname.

**Input Required:** 
* *FILENAME:* Supply the function with a file (*FILENAME*) that has ip addresses to check    
    
**Optional Flags:**
* *-c,--check*: flag to only check the hostnames. Will not update if different  
    
Example commands:

**dnmt direct HostnameUpdate -c *IPList.txt***

This command will check all of the hostnames for IP addresses listed in IPList.txt. 
It will not update if there is a difference, due to the -c flag.

### Upgrade Check

**Description**: This function will take a snapshot of the state of the switch if the apply flag
is not set. If the compare variable  
and if the test flag is not set it will reload the switch. The program will then compare the 
after reload state with the before reload state. This can be run in single mode or batch mode.

#####-Single mode-
**Input Required:** 
* *IP:* Supply the function with an IP of a switch to grab info from & reload
    
**Optional Flags/Commands:**
* *-c,--compare *filename**: option to grab before state from *filename* specified. **WILL NOT** reload
* *-a,--apply*: flag to reload/upgrade switch. **WILL** reload
* *-v,--verbose*: flag to print more info to the terminal.    
   
#####-Batch mode-
**Input Required:** 
* *FILENAME:* Supply the function with a filename with a list of switch IPs to grab info/reload
    
**Optional Flags:**
* *-c,--check*: flag to only grab the state information. Will not reload  
   
Example commands:

**dnmt direct UpgradeCheck single *A.A.A.A***

**dnmt direct UpgradeCheck batch *FILENAME***

### Write Test

**Description**: This function will do a write mem to a switch through snmp. Currently a test function

**Input Required:** 
* *IP:* Supply the function with an ip addresses to write mem    
    
**Optional Flags:**
* *-v,--verbose*: flag to run in verbose mode  
    
Example commands:

**dnmt direct WriteTest  *A.A.A.A***

This command will copy the running config of A.A.A.A to the startup config



[Github-flavored Markdown](https://guides.github.com/features/mastering-markdown/)
 for reference