#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import argparse
import sys
import multiprocessing
import datetime # for logging timestamping

# #local procedure imports relative (for testing)
# from procedure.lefty import Lefty
# from procedure import config
# from procedure import hostnamer


#local procedure imports absolute
from DNMT.procedure.lefty import Lefty
from DNMT.procedure.check import Check
from DNMT.procedure import config
from DNMT.procedure.hostnamer import HostNamer

from DNMT.procedure.statuschecks import StatusChecks
# from DNMT.procedure.SnmpFuncs import SnmpFuncs
# from DNMT.procedure.functions import Functions
from DNMT.procedure.tools import Tools
from DNMT.procedure import hostnamer
from DNMT.procedure.test import Test

#3rd party imports
import argcomplete

#function to allow multiprocessing
def multi_func(functype,cmdargs,config,datavar):
    #print ("ALOHA {}".format(numbera))
    if functype == "UpgradeCheck":
        UpgradeCheck = Check(cmdargs, config)
        UpgradeCheck.single_search(datavar)


def dnmt():

    # load username & password from config.text
    config.load_sw_base_conf()

     ####adding CLI Parsing
    parser = argparse.ArgumentParser(description='Navigate mac address tables to find a specified MAC.')
    subparsers = parser.add_subparsers(help="Choose between interactive or direct functionality", dest ='maincommand')


    # #create subcategory for choosing the interactive parser
    # interactive_parser = subparsers.add_parser("interactive", help= "Interactive Prompt")
    # interactive_parser.add_argument('--interactive',default="True", required=False, help="placeholder variable, ignore")
    #
    # #create subcategory for direct commands (non-interactive) Add parsers here
    # direct_parser = subparsers.add_parser("direct", help= "Non Interactive Commands").add_subparsers(dest="direct")

    #parser commands for MAC Search
    macsearch_parser = subparsers.add_parser("MACSearch", help= "Search for a mac address beginning on a specified switch").add_subparsers(dest="macsearch")
    single_mac_check_parser = macsearch_parser.add_parser("single", help="Search for a single MAC address")
    single_mac_check_parser.add_argument('mac', help='The MAC address to look for')
    single_mac_check_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP to start looking for the mac address at')
    single_mac_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    single_mac_check_parser.add_argument('-c', '--csv', help="save to a specified csv file" )

    batch_mac_check_parser = macsearch_parser.add_parser("batch", help="A single mac address to search for")
    batch_mac_check_parser.add_argument('batchfile', help='File with mac address for batch mode')
    batch_mac_check_parser.add_argument('ipaddr', metavar='IP',
                                         help='The IP to start looking for the mac address at')
    batch_mac_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")
    batch_mac_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")

    general_macsearch_parser = macsearch_parser.add_parser("general",
                                             help="Search for a mac addresses on HP switches").add_subparsers(
        dest="general")
    test_mac_check_parser = general_macsearch_parser.add_parser("single", help="use snmpSearch for a single MAC address")
    test_mac_check_parser.add_argument('mac', help='The MAC address to look for')
    test_mac_check_parser.add_argument('ipaddr', metavar='IP',
                                         help='The IP to start looking for the mac address at')
    test_mac_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")
    test_mac_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")

    test_batch_mac_check_parser = general_macsearch_parser.add_parser("batch", help="use snmpSearch for a batch of MAC addresses")
    test_batch_mac_check_parser.add_argument('batchfile', help='File with mac address for batch mode')
    test_batch_mac_check_parser.add_argument('ipaddr', metavar='IP',
                                         help='The IP to start looking for the mac address at')
    test_batch_mac_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")
    test_batch_mac_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")
    # macsearch_parser.add_argument('-m', '--mac', metavar='macaddr', help="A single mac address to search for")
    # macsearch_parser.add_argument('-b', '--batchfile',metavar = 'BATCHFILE',help="File with mac address for batch mode")


    #parser commands for hostname updater
    hostnameupdate_parser = subparsers.add_parser("HostnameUpdate", help= "Check switch hostnames with their DNS names & update")
    hostnameupdate_parser.add_argument('iplist', metavar='FILENAME',
                        help='The list that contains the ip addresses to check. '
                             'specify "IP,hostname,domain" on each line of the file to not check dns for that ip')
    hostnameupdate_parser.add_argument('-c', '--check', help="Compare hostname, do not change", action="store_true")


    # #parser commands for snmp test (temporary)
    # snmptest_parser = direct_parser.add_parser("SNMPTest", help= "grab snmp variables")
    # snmptest_parser.add_argument('ipaddr', metavar='IP',
    #                     help='The IP of the switch')
    # snmptest_parser.add_argument('oid', metavar='OID',
    #                              help='The OID to check')
    #parser commands for write snmp test (temporary)
    writetest_parser = subparsers.add_parser("WriteTest", help= "grab snmp variables")
    writetest_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP of the switch')
    writetest_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    #parser commands for bulk vlan change (temporary)
    vlanchange_parser = subparsers.add_parser("BulkVlanChange", help= "change all vlans on a switch")
    vlanchange_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP of the switch')
    vlanchange_parser.add_argument('oldvlan', help="Old Vlan ID to change")
    vlanchange_parser.add_argument('newvlan', help="New Vlan ID to change to")

    #parser for Checking on reloads
    check_parser = subparsers.add_parser("UpgradeCheck",
                                     help="Commands to verify upgrade of switches").add_subparsers(dest="upgradecheck")
    single_check_parser = check_parser.add_parser("single", help="single ip to check")
    single_check_parser.add_argument('ipaddr', metavar='IP', help='The IP to check')
    single_check_parser.add_argument('-a', '--apply', help="Perform full reload/upgrade", default=False, action="store_true")
    single_check_parser.add_argument('-s', '--skip', help="skip verification", default=False,
                                    action="store_true")
    single_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    single_check_parser.add_argument('-c', '--compare', help="specify config file to match current config")
    single_check_parser.add_argument('-d', '--delay', help="specify minutes to delay reload (If Applying)")
    single_check_parser.add_argument('-u', '--updateinterval',
                                    help="specify the check interval in seconds after reload (If Applying)"
                                         "Default is 30")

    batch_check_parser = check_parser.add_parser("batch", help="multiple ips to check")
    batch_check_parser.add_argument('file', metavar='file',help='The file with IPs to check')
    batch_check_parser.add_argument('-a', '--apply', help="Perform full reload/upgrade", default=False, action="store_true")
    batch_check_parser.add_argument('-s', '--skip', help="skip verification", default=False,
                                    action="store_true")
    batch_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    batch_check_parser.add_argument('-c', '--compare', help="specify config file to match current config")
    batch_check_parser.add_argument('-d', '--delay', help="specify minutes to delay reload (If Applying)")
    batch_check_parser.add_argument('-u', '--updateinterval', help="specify the check interval in seconds after reload (If Applying)"
                                                                   "Default is 30")
    #Status Checking parsers
    status_checks_parser = subparsers.add_parser("StatusChecks", help="functions regarding checking the status of switches").add_subparsers(dest="statuschecks")
    maintenance_parser = status_checks_parser.add_parser("maintenance",help="perform maintenance (clean up)")
    maintenance_parser.add_argument('maxfiles', help="Max number of statuscheck files to keep")
    maintenance_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                          action="store_true")
    maintenance_parser.add_argument('-t', '--test', help="don't delete anything, just test", default=False, action="store_true")
    activity_tracking_parser = status_checks_parser.add_parser("Activity_Tracking", help="check if port status has changed")
    activity_tracking_parser.add_argument('-f', '--file', help="specify iplist file to use if not using default")
    activity_tracking_parser.add_argument('-e', '--email', help="specify which email to send file to")
    activity_tracking_parser.add_argument('-n', '--numprocs', help="specify how many concurrent processes")
    activity_tracking_parser.add_argument('-p', '--parallel', help="run grab processes in parallel", default=False,
                                          action="store_true")
    activity_tracking_parser.add_argument('-l', '--limit', help="only put switches specified in iplist in summary file",
                                          default=False, action="store_true")
    activity_tracking_parser.add_argument('-c', '--check', help="Operate on existing statcheck files, no log ins",
                                          default=False, action="store_true")
    activity_tracking_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                          action="store_true")
    activity_tracking_parser.add_argument('-m', '--maxentries', help="modify max number of historical entries")

    switch_check_parser = status_checks_parser.add_parser("Switch_Check", help="check switch info")
    switch_check_parser.add_argument('-i', '--ipaddr', metavar='IP', help='Switch Address interface is on')
    switch_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")
    switch_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    switch_check_parser.add_argument('-l', '--load', help="load switchstruct from a specified file")

    #Tests Begin
    test_parser = subparsers.add_parser("test", help="various tests").add_subparsers(dest="test")
    command_blaster_parser = test_parser.add_parser("Command_Blaster", help="send some non-enabled commands")
    command_blaster_parser.add_argument('ipaddrfile', help='text file with switch addresses to run commands on')
    command_blaster_parser.add_argument('commandfile', help='text file with commands to run')
    error_counter_parser = test_parser.add_parser("Error_Counter", help="check the errors of an interface")
    error_counter_parser.add_argument('ipaddr', help='address of switch to check')
    error_counter_parser.add_argument('interface', help='string to grab error counts of example:8/10')
    error_counter_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    bad_phone_parser = test_parser.add_parser("BadPhone", help="look for bad phones")
    bad_phone_parser.add_argument('file', metavar='file',help='The file with IPs to check')
    bad_phone_parser.add_argument('-s', '--skip', help="skip verification", default=False, action="store_true")
    dell_snmp_parser = test_parser.add_parser("dellsnmp", help="add snmp ro string")
    dell_snmp_parser.add_argument('file', metavar='file', help='The file with IPs to check')
    dell_snmp_parser.add_argument('snmpstring', metavar='snmpstring', help="snmp string to add")



    #Tests End


    # create subcategory for tools
    tools_parser = subparsers.add_parser("tools", help="various tools").add_subparsers(dest="tools")

    port_change_parser = tools_parser.add_parser("Port_Change", help="update a port")
    port_change_parser.add_argument('ipaddr', metavar='IP', help='Switch Address interface is on')
    port_change_parser.add_argument('interface', metavar='interface', help='interface to update')
    # vlan_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")


    # parser commands for AP_Poke
    appoke_parser = tools_parser.add_parser("AP_Poke", help="Toggle APs with issues")
    appoke_parser.add_argument('ipaddr', metavar='IP', help='Switch Address AP is on')
    appoke_parser.add_argument('interface', metavar='interface', help='interface AP is on')
    appoke_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    appoke_parser.add_argument('-s', '--skip', help="skip verification", default=False,action="store_true")
    appoke_parser.add_argument('-t', '--tdr', help="perform TDR test", default=False, action="store_true")
    appoke_parser.add_argument('-l', '--login', help="Ask for login credentials", default=False, action="store_true")

    #diggle functionality
    dig_tool_parser = tools_parser.add_parser("dig", help="List hostnames from dns by domain")
    dig_tool_parser.add_argument('domain', help='domain to do a zone transfer from')
    dig_tool_parser.add_argument('hoststring', help='things to match on for DNS names ie: switch-location-place')
    dig_tool_parser.add_argument('-a', '--advanced', help="Gather more info about hosts", default=False, action="store_true")



    argcomplete.autocomplete(parser)
    cmdargs = parser.parse_args()

#change these to only creating if required
    macsearcher = Lefty(cmdargs,config)
    hostnamer = HostNamer(cmdargs,config)
    upgradeCheck = Check(cmdargs, config)
    statusChecks = StatusChecks(cmdargs,config)
    tools = Tools(cmdargs, config)
    # functions = Functions(cmdargs,config)
    # snmpFuncs = SnmpFuncs(cmdargs,config)
    test = Test(cmdargs, config)

    ### complete CLI Parsing

    #create the loop for interactive prompt

    if cmdargs.maincommand == "MACSearch":
        if cmdargs.macsearch == 'single' or cmdargs.macsearch == 'batchfile':
            macsearcher.begin_search()
        elif cmdargs.macsearch =='general':
            macsearcher.begin_snmp_search()
    elif cmdargs.maincommand == "HostnameUpdate":
        hostnamer.hostname_update()
    # elif args.direct == "SNMPTest":
    #     hostnamer.snmp_test(args.ipaddr, config, args.oid)
    elif cmdargs.maincommand == "WriteTest":
        #hostnamer.write_test(cmdargs.ipaddr, config)
        hostnamer.write_test(cmdargs.ipaddr)
    elif cmdargs.maincommand == "BulkVlanChange":
        hostnamer.bulk_vlan_change(cmdargs.ipaddr,cmdargs.oldvlan,int(cmdargs.newvlan))
    elif cmdargs.maincommand == "UpgradeCheck":
        #UpgradeCheck.main()

        if cmdargs.upgradecheck == 'single' and cmdargs.ipaddr:
            #upgradeCheck.single_search(cmdargs.ipaddr)
            upgradeCheck.begin()
        elif cmdargs.upgradecheck == 'batch' and cmdargs.file:
            upgradeCheck.begin()
    elif cmdargs.maincommand == "tools":
        if cmdargs.tools == 'AP_Poke':
            try:  #<TODO ADD THIS FUNCTIONALITY EVERYWHERE>
                tools.Ap_Poke()
            except SystemExit as errcode:
                sys.exit(errcode)
        elif cmdargs.tools == 'Port_Change':
            tools.Change_Port_Vlan()
        elif cmdargs.tools =='dig':
            tools.diggle()
    elif cmdargs.maincommand == 'StatusChecks':
        if cmdargs.statuschecks == "Activity_Tracking":
            statusChecks.Activity_Tracking_Begin()
        elif cmdargs.statuschecks == "Switch_Check":
            statusChecks.Switch_Check()
        elif cmdargs.statuschecks == "maintenance":
            try:
                statusChecks.Maintenance(int(cmdargs.maxfiles))
            except ValueError:
                print("maxfiles is not a number, exiting")
    elif cmdargs.maincommand == 'test':
        if cmdargs.test == 'Command_Blaster':
            test.Command_Blaster_Begin()
        elif cmdargs.test == 'Error_Counter':
            test.Error_Check()
        elif cmdargs.test == 'BadPhone':
            test.BadPhoneBegin()
        elif cmdargs.test == "dellsnmp":
            test.dell_snmp_Begin()






                # ####         add mapping to verify order to reload here            ###
                #
                # procs = []
                # for index, number in enumerate(iplist):
                #     #proc = Process(target=single_search, args=(number,))
                #     proc = Process(target=multi_func, args=("UpgradeCheck",cmdargs,config,number,))
                #     procs.append(proc)
                #     proc.start()
                #
                # for proc in procs:
                #     proc.join()



if __name__ == "__main__":
    dnmt()