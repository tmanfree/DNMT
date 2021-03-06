# Direct Network Management Tool (DNMT)


The Direct Network Management Tool *(DNMT)* is intended to house various functions that
require directly accessing switches through either SSH or SNMP. **All functions have the -h flag that will
*not* run the program, but will return with a help text that should provide more information on how to run it.**

 
 A config file (config.text) is required to get user information (username/pass/snmp/etc)

Current functionality:

* **MAC Search** - *dnmt.py mac_search  -m MAC START_IP*. Based on the previous "Lefty" program,
 this is currently operational

* **Hostname Update** - *dnmt.py hostname_update FILENAME*. This will compare switch hostnames
with dns hostnames, updating the switch hostname if they are different.

* **WriteTest** - *dnmt.py write_test IP*. This performs a "write mem" through snmp. **May not trigger archival in 
cisco prime*

* **Bulk Vlan Change** - *dnmt.py bulk_vlan_change IP Oldvlan Newvlan*. This will change all ports on "oldvlan" 
to be on "newvlan".

* **Upgrade Check** - *dnmt.py upgrade_check [single|batch] IP|IPFILE*. This will perform some checks 
before upgrading. Can also apply upgrades by restarting switches and then checking the state against the pre-reload
state. Can be run in single or batch mode.

* **AP toggle** - *dnmt.py tools ap_poke IP Interface*. This will perform a "shut/no shut" on a port if it is deemed
safe to do so.

* **Port Vlan Change** - *dnmt.py tools port_change IP Interface*. This will provide an interactive prompt to
change the vlan on an interface.

* **Switch Check** - *dnmt.py status_checks switch_check*. Grab a variety of switch status data through snmp.

* **Activity Tracking** - *dnmt.py status_checks sctivity_tracking*. grab switch struct data and compare it to existing data.

* **Standardize** - *dnmt.py tools standardize*. apply commands to a switch if they are missing.

* **Mapper** - *dnmt.py mapper ip_filename*. map out the cdp connections of all the provided IPs.

* **Test Commands** - *dnmt.py test {command}*. A variety of commands that are added/removed as required [buggy cmds here]

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

    dnmt mac_search -m AAAA.BBBB.CCCC 1.1.1.1

This command will search for MAC address *AAAA.BBBB.CCCC* starting from IP address 1.1.1.1

    dnmt mac_search -b macfile.txt 1.1.1.1 -c output.csv

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

    dnmt hostname_update -c IPList.txt

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
* *-s,--skip*: flag to skip flash verifications.
* *-v,--verbose*: flag to print more info to the terminal.    
   
#####-Batch mode-
**Input Required:** 
* *FILENAME:* Supply the function with a filename with a list of switch IPs to grab info/reload
    
**Optional Flags:**
* *-c,--compare *filename**: option to grab before state from *filename* specified. **WILL NOT** reload
* *-a,--apply*: flag to reload/upgrade switch. **WILL** reload
* *-s,--skip*: flag to skip flash verifications.
* *-v,--verbose*: flag to print more info to the terminal.   

   
Example commands:

    dnmt upgrade_check single A.A.A.A

    dnmt upgrade_check batch FILENAME

### Write Test

**Description**: This function will do a write mem to a switch through snmp. Currently a test function

**Input Required:** 
* *IP:* Supply the function with an ip addresses to write mem    
    
**Optional Flags:**
* *-v,--verbose*: flag to run in verbose mode  
    
Example commands:

    dnmt write_test  A.A.A.A

This command will copy the running config of A.A.A.A to the startup config

###Bulk Vlan Change
 
 **Description:** This function will change all ports assigned to one vlan to another vlan. Useful for changing 
 vlan IDs.
 
 **Input Required:**
 * *IP:* The IP address of the switch to change vlan assignments
 * *oldvlan:* The vlan that will have ports assigned from
 * *newvlan:* The vlan that will have ports assigned to
 
Example Commands:
 
    dnmt.py bulk_vlan_change A.A.A.A 500 901
 
This will change all ports on A.A.A.A on vlan 500 to vlan 901. 

###AP toggle

 **Description:** This will perform a "shut/no shut" on a port if it is deemed
safe to do so. Will only toggle if the port is down, or up with an AP, or up with Ieee and 0 mac addresses.
 
 **Input Required:**
 * *IP:* The IP address of the switch to toggle a port
 * *interface* The interface to check/toggle
 
 **Optional Flags**
* *-v, --verbose*  run in verbose mode
* *-s, --skip*     skip verification
* *-t, --tdr*      perform TDR test
* *-l, --login*    Ask for login credentials, helpful for non standard switches

Example Commands:

    dnmt.py tools ap_poke A.A.A.A 1/0/1 -v

This will check port 1/0/1 on switch A.A.A.A to see if it is safe to toggle. If so, it will ask if you want to do so.
More information will be printed to the screen as it is in verbose mode. 

###Port vlan change

**Description:** This will provide an interactive prompt to change the vlan of an interface. All available vlans will
be listed, then the current vlan on the port will be shown. The user will then be prompted for what vlan to place the 
port on.

 **Input Required:**
 * *IP:* The IP address of the switch to update the vlan of an interface
 * *interface* The interface to change the vlan of

Example Commands:

    dnmt.py tools port_change A.A.A.A 1/0/1

This will provide an interactive prompt to change the vlan on port 1/0/1 of switch A.A.A.A

###Switch_Check
**Description:** This will poll a series of snmp OIDs to gather information on the state of a switch. The program
will then output it to the screen, or to a csv file if specified.

 **Input Required:**
 * *-i IP* The IP address of the switch to gather status information from
 * -or-
 * *-l FILE* File to load a switch structure from a file

 **Optional Flags**
* *-v, --verbose*  run in verbose mode
* *-c, --CSV*     create a CSV file of status

Example Commands:

    dnmt.py status_checks switch_check -i A.A.A.A -c CSV.csv

This will grab switch status information from switch A.A.A.A and output to a file called CSV.csv

###Activity_Tracking
**Description:** This will gather switch status and compare it against any pre existing ones. After comparing, it will
create a summary file and email it

 **Input Required:**
 * *NONE* - By default, it will check /usr/lib/capt/activitycheckIPlist to get a list of IPs to process. 
 
 **Optional Flags**

*  *-f , --file* specify iplist file to use if not using default
*  *-e, --email* specify which email to send file to
*  *-n, --numprocs* specify how many concurrent processes
*  *-p, --parallel*        run grab processes in parallel
*  *-l, --limit*           only put switches specified in iplist in summary file
*  *-c, --check*           Operate on existing statcheck files, no log ins
*  *-m, --maxentries* modify max number of historical entries to keep for ports
*  *-v, --verbose*         run in verbose mode                        

Example Commands:

    dnmt.py status_checks activity_tracking -l -e test@email.com

This will operate on all ips listed in /usr/lib/capt/activitycheckIPlist, compare against all existing 
 statcheck files, create a summary file using only the ips listed in activitycheckIPlist then email to test@email.com 
 
 
 ###Mapper
**Description:** This will check the cdp neighbour entries of switches supplied to it and map it out using graphviz.
If an email is specified it will email the png file, otherwise it will print out a text connection display.
Currently has hard set ignore of VG,ATA and Phones and ignores specific hostnames.
[requires graphviz runtimes on generating machine]

 **Input Required:**
 * *filename* - a text file containing all IP seed addresses to check. one IP per line. 
 
 **Optional Flags**

*  *-f , --file* specify iplist file to use if not using default
*  *-h, --help*            show this help message and exit
*  *-v, --verbose*         run in verbose mode
*  *-t, --test*            don't delete anything, just test
*  *-d, --debug*           run in debug mode (extremely verbose)
*  *-e EMAIL, --email EMAIL* specify email to send graph to
*  *-r, --remove*          remove file after processing                   

Example Commands:

    dnmt.py mapper ip_file -e test@email.com -r

This will generate a cdp map using all the ips in ip_file (and any it sees/can log into) then email to test@email.com.
It will remove the png after sending.


###Test Commands
Commands that are being tested out before moving into permanence
####Switch_Check
Grab the state of the switch through snmp 
####Command_Blaster
send some non-enabled commands
####Error_Counter
check the errors of an interface
####BadPhone
look for bad phones (Ieee and notconnect)



[Github-flavored Markdown](https://guides.github.com/features/mastering-markdown/)
 for reference