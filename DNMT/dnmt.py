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
from DNMT.procedure.SnmpFuncs import SnmpFuncs
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
    macsearch_parser = subparsers.add_parser("MACSearch", help= "Search for a mac address beginning on a specified switch")
    macsearch_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP to start looking for the mac address at')
    macsearch_parser.add_argument('-m', '--mac', metavar='macaddr', help="A single mac address to search for")
    macsearch_parser.add_argument('-b', '--batchfile',metavar = 'BATCHFILE',help="File with mac address for batch mode")
    macsearch_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    macsearch_parser.add_argument('-c', '--csv', help="save to a specified csv file" )

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
    batch_check_parser = check_parser.add_parser("batch", help="multiple ips to check")
    batch_check_parser.add_argument('file', metavar='file',help='The file with IPs to check')
    batch_check_parser.add_argument('-a', '--apply', help="Perform full reload/upgrade", default=False, action="store_true")
    batch_check_parser.add_argument('-s', '--skip', help="skip verification", default=False,
                                    action="store_true")
    batch_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    batch_check_parser.add_argument('-c', '--compare', help="specify config file to match current config")



    #Tests Begin
    test_parser = subparsers.add_parser("test", help="various tests").add_subparsers(dest="test")
    power_check_parser = test_parser.add_parser("Power_Check", help="check port power")
    power_check_parser.add_argument('ipaddr', metavar='IP', help='Switch Address interface is on')
    switch_check_parser = test_parser.add_parser("Switch_Check", help="check switch info")
    switch_check_parser.add_argument('ipaddr', metavar='IP', help='Switch Address interface is on')
    switch_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")
    command_blaster_parser = test_parser.add_parser("Command_Blaster", help="send some non-enabled commands")
    command_blaster_parser.add_argument('ipaddrfile', help='text file with switch addresses to run commands on')
    command_blaster_parser.add_argument('commandfile', help='text file with commands to run')



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



    argcomplete.autocomplete(parser)
    cmdargs = parser.parse_args()

#change these to only creating if required
    macsearcher = Lefty(cmdargs,config)
    hostnamer = HostNamer(cmdargs,config)
    upgradeCheck = Check(cmdargs, config)
    tools = Tools(cmdargs, config)
    snmpFuncs = SnmpFuncs(cmdargs,config)
    test = Test(cmdargs, config)

    ### complete CLI Parsing

    #create the loop for interactive prompt

    if cmdargs.maincommand == "MACSearch":
        macsearcher.begin_search()
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
            snmpFuncs.Change_Port_Vlan()
    elif cmdargs.maincommand == 'test':
        if cmdargs.test == 'Power_Check':
            test.Power_Check()
        elif cmdargs.test == 'Switch_Check':
            test.Switch_Check()
        elif cmdargs.test == 'Command_Blaster':
            test.Command_Blaster_Begin()





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