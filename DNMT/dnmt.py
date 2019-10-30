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
from DNMT.procedure.tools import Tools
from DNMT.procedure import hostnamer

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
    subparsers = parser.add_subparsers(help="Choose between interactive or direct functionality")


    #create subcategory for choosing the interactive parser
    interactive_parser = subparsers.add_parser("interactive", help= "Interactive Prompt")
    interactive_parser.add_argument('--interactive',default="True", required=False, help="placeholder variable, ignore")

    #create subcategory for direct commands (non-interactive) Add parsers here
    direct_parser = subparsers.add_parser("direct", help= "Non Interactive Commands").add_subparsers(dest="direct")

    #parser commands for MAC Search
    macsearch_parser = direct_parser.add_parser("MACSearch", help= "Search for a mac address beginning on a specified switch")
    macsearch_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP to start looking for the mac address at')
    macsearch_parser.add_argument('-m', '--mac', metavar='macaddr', help="A single mac address to search for")
    macsearch_parser.add_argument('-b', '--batchfile',metavar = 'BATCHFILE',help="File with mac address for batch mode")
    macsearch_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    macsearch_parser.add_argument('-c', '--csv', help="save to a specified csv file" )

    #parser commands for hostname updater
    hostnameupdate_parser = direct_parser.add_parser("HostnameUpdate", help= "Check switch hostnames with their DNS names & update")
    hostnameupdate_parser.add_argument('iplist', metavar='FILENAME',
                        help='The list that contains the ip addresses to check')
    hostnameupdate_parser.add_argument('-c', '--check', help="Compare hostname, do not change", action="store_true")

    # #parser commands for snmp test (temporary)
    # snmptest_parser = direct_parser.add_parser("SNMPTest", help= "grab snmp variables")
    # snmptest_parser.add_argument('ipaddr', metavar='IP',
    #                     help='The IP of the switch')
    # snmptest_parser.add_argument('oid', metavar='OID',
    #                              help='The OID to check')
    #parser commands for write snmp test (temporary)
    writetest_parser = direct_parser.add_parser("WriteTest", help= "grab snmp variables")
    writetest_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP of the switch')
    writetest_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    #parser commands for bulk vlan change (temporary)
    vlanchange_parser = direct_parser.add_parser("BulkVlanChange", help= "change all vlans on a switch")
    vlanchange_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP of the switch')
    vlanchange_parser.add_argument('oldvlan', help="Old Vlan ID to change")
    vlanchange_parser.add_argument('newvlan', help="New Vlan ID to change to")

    #parser for Checking on reloads
    check_parser = direct_parser.add_parser("UpgradeCheck",
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

    # create subcategory for tools
    tools_parser = direct_parser.add_parser("tools", help="various tools").add_subparsers(dest="tools")

    # parser commands for MAC Search
    appoke_parser = tools_parser.add_parser("AP_Poke", help="Toggle APs with issues")
    appoke_parser.add_argument('ipaddr', metavar='IP', help='Switch Address AP is on')
    appoke_parser.add_argument('interface', metavar='interface', help='interface AP is on')
    appoke_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")



    argcomplete.autocomplete(parser)
    cmdargs = parser.parse_args()

#change these to only creating if required
    macsearcher = Lefty(cmdargs,config)
    hostnamer = HostNamer(cmdargs,config)
    upgradeCheck = Check(cmdargs, config)
    tools = Tools(cmdargs, config)

    ### complete CLI Parsing


    #create the loop for interactive prompt
    if "interactive" in cmdargs :
        print("Functionality under construction :(")

        # logbool = False #boolean to check current logging state
        # completebool = False #boolean to allow exiting out of the loop
        # while not completebool:
        # # Display the menu
        #     OpCode = input("Enter the operation you want to do:\n"
        #                        "(1) MAC Searcher - Track down MACs through CDP Neighbour\n"
        #                        "(2) Hostname Updater\n"
        #                        "(L) Enable Logging\n"
        #                        "(Q) Quit\n"
        #                        "Choice=")
        # # if Mac Searcher selected, use the 'lefty' function
        #     if OpCode == '1':
        #         #add error handling
        #         macsearcher.cmdargs.ipaddr = input("Enter the switch to start searching on:")
        #         macaddr = input("Enter the mac address to search for (can be last 4 digits)")
        #         macsearcher.unified_search([macsearcher.normalize_mac(macaddr)])
        #     elif OpCode == '2':
        #         iplist = input("Enter the name of the file containing IPs of switches to update:")
        #         Hostnamer.hostname_update()
        #     elif OpCode.upper() == 'L':
        #         print("Under construction")
        #     elif OpCode.upper() == 'Q':
        #         print("Exiting")
        #         completebool = True
        #         sys.exit()
    elif 'direct' in cmdargs:
        if cmdargs.direct == "MACSearch":
            macsearcher.begin_search()
        elif cmdargs.direct == "HostnameUpdate":
            hostnamer.hostname_update()
        # elif args.direct == "SNMPTest":
        #     hostnamer.snmp_test(args.ipaddr, config, args.oid)
        elif cmdargs.direct == "WriteTest":
            #hostnamer.write_test(cmdargs.ipaddr, config)
            hostnamer.write_test(cmdargs.ipaddr)
        elif cmdargs.direct == "BulkVlanChange":
            hostnamer.bulk_vlan_change(cmdargs.ipaddr,cmdargs.oldvlan,int(cmdargs.newvlan))
        elif cmdargs.direct == "UpgradeCheck":
            #UpgradeCheck.main()

            if cmdargs.upgradecheck == 'single' and cmdargs.ipaddr:
                upgradeCheck.single_search(cmdargs.ipaddr)
            elif cmdargs.upgradecheck == 'batch' and cmdargs.file:
                upgradeCheck.begin()
        elif cmdargs.direct == "tools":
            if cmdargs.tools == 'AP_Poke':
                tools.Ap_Poke()

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