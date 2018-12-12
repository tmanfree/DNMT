#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import argparse
import sys
import datetime # for logging timestamping

#local procedure imports
from DNMT.procedure.lefty import Lefty
from DNMT.procedure import config
from DNMT.procedure import hostnamer

#3rd party imports
import argcomplete




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

    #parser commands for snmp test (temporary)
    snmptest_parser = direct_parser.add_parser("SNMPTest", help= "grab snmp variables")
    snmptest_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP of the switch')
    snmptest_parser.add_argument('oid', metavar='OID',
                                 help='The OID to check')
    #parser commands for write snmp test (temporary)
    writetest_parser = direct_parser.add_parser("WriteTest", help= "grab snmp variables")
    writetest_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP of the switch')




    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    macsearcher = Lefty(args,config)

    ### complete CLI Parsing


    #create the loop for interactive prompt
    if "interactive" in args :

        logbool = False #boolean to check current logging state
        completebool = False #boolean to allow exiting out of the loop
        while not completebool:
        # Display the menu
            OpCode = input("Enter the operation you want to do:\n"
                               "(1) MAC Searcher - Track down MACs through CDP Neighbour\n"
                               "(2) Hostname Updater\n"                       
                               "(L) Enable Logging\n"
                               "(Q) Quit\n"
                               "Choice=")
        # if Mac Searcher selected, use the 'lefty' function
            if OpCode == '1':
                #add error handling
                macsearcher.args.ipaddr = input("Enter the switch to start searching on:")
                macaddr = input("Enter the mac address to search for (can be last 4 digits)")
                macsearcher.unified_search([macsearcher.normalize_mac(macaddr)])
            elif OpCode == '2':
                iplist = input("Enter the name of the file containing IPs of switches to update:")
                hostnamer.hostname_update(iplist,config.username,config.password,config.ro,config.rw)
            elif OpCode.upper() == 'L':
                print("Under construction")
            elif OpCode.upper() == 'Q':
                print("Exiting")
                completebool = True
                sys.exit()
    elif 'direct' in args:
        if args.direct == "MACSearch":
            macsearcher.begin_search()
        elif args.direct == "HostnameUpdate":
            hostnamer.hostname_update(args.iplist, config, args.check)
        elif args.direct == "SNMPTest":
            hostnamer.snmp_test(args.ipaddr, config, args.oid)
        elif args.direct == "WriteTest":
            hostnamer.write_test(args.ipaddr, config)

if __name__ == "__main__":
    dnmt()
#### Done CLI Parsing