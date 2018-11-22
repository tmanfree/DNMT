#!/usr/bin/env python3

import argparse
import sys


from procedure import lefty
from procedure import config
# load username & password from config.text
config.load_sw_base_conf()

 ####adding CLI Parsing
parser = argparse.ArgumentParser(description='Navigate mac address tables to find a specified MAC.')
#subparsers = parser.add_subparsers(help="Choose between interactive or direct functionality")
subparsers = parser.add_subparsers(help="Choose between interactive or direct functionality")


#create subcategory for choosing the interactive parser
interactive_parser = subparsers.add_parser("interactive", help= "Interactive Prompt")
interactive_parser.add_argument('--interactive',default="True", required=False, help="placeholder variable, ignore")

#create subcategory for direct commands (non-interactive) Add parsers here
#direct_parser = subparsers.add_parser("direct", help= "Non Interactive Commands")
direct_parser = subparsers.add_parser("direct", help= "Non Interactive Commands").add_subparsers(dest="direct")
#direct_parser.add_subparsers(dest = "direct") = subparsers.add_parser("direct", help= "Non Interactive Commands")

#parser commands for MAC Search
macsearch_parser = direct_parser.add_parser("MACSearch", help= "Search for a mac address beginning on a specified switch")
macsearch_parser.add_argument('ipaddr', metavar='IP',
                    help='The IP to start looking for the mac address at')
macsearch_parser.add_argument('macaddr', metavar='MAC',
                    help='The MAC address to search for ')


#parser.add_argument('ipfile', metavar='IPFILE',
#                    help='The file that contains IP addresses to check')

args = parser.parse_args()
#print (args)
### complete CLI Parsing


#create the loop for interactive prompt
if "interactive" in args :

    logbool = False #boolean to check current logging state
    completebool = False #boolean to allow exiting out of the loop
    while not completebool:
    # Display the menu
        OpCode = int(input("Enter the operation you want to do:\n"
                           "(1) MAC Searcher - Track down MACs through CDP Neighbour\n"
                           "(2) Option 2\n"                       
                           "(3) Enable Logging\n"
                           "(4) Quit\n"
                           "Choice="))
    # if Mac Searcher selected, use the 'lefty' function
        if OpCode == 1:
            #add error handling
            ipaddr = input("Enter the switch to start searching on:")
            macaddr = input("Enter the mac address to search for (can be last 4 digits)")
            lefty.mac_search(ipaddr,macaddr,config.username,config.password)
        elif OpCode ==2:
            print("option 2")
        elif OpCode == 3:
            print("Exiting")
            completebool = True
            sys.exit()
elif 'direct' in args:
    lefty.mac_search(args.ipaddr, args.macaddr, config.username, config.password)
#input_vals = {'IP':args.ipfile}
print
#### Done CLI Parsing