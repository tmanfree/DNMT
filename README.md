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


##Detailed function breakdowns

####MAC Search

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





[Github-flavored Markdown](https://guides.github.com/features/mastering-markdown/)
 for reference