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
from DNMT.procedure.dbcmds import DBcmds
from DNMT.procedure.mapper import Mapper
from DNMT.procedure.archivist import Archivist

from DNMT.procedure.statuschecks import StatusChecks
# from DNMT.procedure.SnmpFuncs import SnmpFuncs
# from DNMT.procedure.functions import Functions
from DNMT.procedure.tools import Tools
from DNMT.procedure import hostnamer
from DNMT.procedure.test import Test
from DNMT.procedure.mactracking import MacTracking

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
    mac_search_parser = subparsers.add_parser("mac_search", help= "Search for a mac address beginning on a specified switch").add_subparsers(dest="mac_search")
    single_mac_check_parser = mac_search_parser.add_parser("single", help="Search for a single MAC address")
    single_mac_check_parser.add_argument('mac', help='The MAC address to look for')
    single_mac_check_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP to start looking for the mac address at')
    single_mac_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    single_mac_check_parser.add_argument('-c', '--csv', help="save to a specified csv file" )

    batch_mac_check_parser = mac_search_parser.add_parser("batch", help="A single mac address to search for")
    batch_mac_check_parser.add_argument('batchfile', help='File with mac address for batch mode')
    batch_mac_check_parser.add_argument('ipaddr', metavar='IP',
                                         help='The IP to start looking for the mac address at')
    batch_mac_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")
    batch_mac_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")

    general_mac_search_parser = mac_search_parser.add_parser("general",
                                             help="Search for a mac addresses on HP switches").add_subparsers(
        dest="general")
    test_mac_check_parser = general_mac_search_parser.add_parser("single", help="use snmpSearch for a single MAC address")
    test_mac_check_parser.add_argument('mac', help='The MAC address to look for')
    test_mac_check_parser.add_argument('ipaddr', metavar='IP',
                                         help='The IP to start looking for the mac address at')
    test_mac_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")
    test_mac_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")

    test_batch_mac_check_parser = general_mac_search_parser.add_parser("batch", help="use snmpSearch for a batch of MAC addresses")
    test_batch_mac_check_parser.add_argument('batchfile', help='File with mac address for batch mode')
    test_batch_mac_check_parser.add_argument('ipaddr', metavar='IP',
                                         help='The IP to start looking for the mac address at')
    test_batch_mac_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")
    test_batch_mac_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")
    # mac_search_parser.add_argument('-m', '--mac', metavar='macaddr', help="A single mac address to search for")
    # mac_search_parser.add_argument('-b', '--batchfile',metavar = 'BATCHFILE',help="File with mac address for batch mode")


    #parser commands for hostname updater
    hostname_update_parser = subparsers.add_parser("hostname_update", help= "Check switch hostnames with their DNS names & update")
    hostname_update_parser.add_argument('iplist', metavar='FILENAME',
                        help='The list that contains the ip addresses to check. '
                             'specify "IP,hostname,domain" on each line of the file to not check dns for that ip')
    hostname_update_parser.add_argument('-c', '--check', help="Compare hostname, do not change", action="store_true")
    hostname_update_parser.add_argument('-p', '--peek', help="Peek at DNS, do not login to switch", action="store_true")
    hostname_update_parser.add_argument('-d', '--debug', help="Extremely verbose mode", action="store_true")
    hostname_update_parser.add_argument('-v', '--verbose', help="verbose mode", action="store_true")




    # #parser commands for snmp test (temporary)
    # snmptest_parser = direct_parser.add_parser("SNMPTest", help= "grab snmp variables")
    # snmptest_parser.add_argument('ipaddr', metavar='IP',
    #                     help='The IP of the switch')
    # snmptest_parser.add_argument('oid', metavar='OID',
    #                              help='The OID to check')
    #parser commands for write snmp test (temporary)
    write_test_parser = subparsers.add_parser("write_test", help= "grab snmp variables")
    write_test_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP of the switch')
    write_test_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    #parser commands for bulk vlan change (temporary)
    vlan_change_parser = subparsers.add_parser("bulk_vlan_change", help= "change all vlans on a switch")
    vlan_change_parser.add_argument('ipaddr', metavar='IP',
                        help='The IP of the switch')
    vlan_change_parser.add_argument('oldvlan', help="Old Vlan ID to change")
    vlan_change_parser.add_argument('newvlan', help="New Vlan ID to change to")

    #parser for Checking on reloads
    upgrade_check_parser = subparsers.add_parser("upgrade_check",
                                     help="Commands to verify upgrade of switches").add_subparsers(dest="upgrade_check")
    single_upgrade_check_parser = upgrade_check_parser.add_parser("single", help="single ip to check")
    single_upgrade_check_parser.add_argument('ipaddr', metavar='IP', help='The IP to check')
    single_upgrade_check_parser.add_argument('-a', '--apply', help="Perform full reload/upgrade", default=False, action="store_true")
    single_upgrade_check_parser.add_argument('-s', '--skip', help="skip verification", default=False,
                                    action="store_true")
    single_upgrade_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    single_upgrade_check_parser.add_argument('-c', '--compare', help="specify config file to match current config")
    single_upgrade_check_parser.add_argument('-d', '--delay', help="specify minutes to delay reload (If Applying)")
    single_upgrade_check_parser.add_argument('-u', '--updateinterval',
                                    help="specify the check interval in seconds after reload (If Applying)"
                                         "Default is 30")

    batch_upgrade_check_parser = upgrade_check_parser.add_parser("batch", help="multiple ips to check")
    batch_upgrade_check_parser.add_argument('file', metavar='file',help='The file with IPs to check')
    batch_upgrade_check_parser.add_argument('-a', '--apply', help="Perform full reload/upgrade", default=False, action="store_true")
    batch_upgrade_check_parser.add_argument('-s', '--skip', help="skip verification", default=False,
                                    action="store_true")
    batch_upgrade_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    batch_upgrade_check_parser.add_argument('-c', '--compare', help="specify config file to match current config")
    batch_upgrade_check_parser.add_argument('-d', '--delay', help="specify minutes to delay reload (If Applying)")
    batch_upgrade_check_parser.add_argument('-u', '--updateinterval', help="specify the check interval in seconds after reload (If Applying)"
                                                                   "Default is 30")
    #viewlog functionality #integrate with regular updatecheck? single and batch? print first line of sum file for status
    view_log_upgrade_check_parser = upgrade_check_parser.add_parser("view_log", help="parse logs for easier viewing")
    view_log_upgrade_check_parser.add_argument('ipaddr', metavar='IP', help='The IP to check')
    # viewlog_check_parser = check_parser.add_parser("viewlog", help="parse logs for easier viewing").add_subparsers(dest="viewlog")
    # before_viewlog_check_parser = viewlog_check_parser.add_parser('before', help="check before file of an IP")
    # before_viewlog_check_parser.add_argument('ipaddr', metavar='IP', help='The IP to check')
    # after_viewlog_check_parser = viewlog_check_parser.add_parser('after', help="check after file of an IP")#THERE ARE AFTERS AND RELOADS
    # after_viewlog_check_parser.add_argument('ipaddr', metavar='IP', help='The IP to check')

    # mac Checking parsers
    mac_checks_parser = subparsers.add_parser("mac_checks",
                                                 help="functions regarding checking mac address locations").add_subparsers(
        dest="mac_checks")
    # maintenance_parser = status_checks_parser.add_parser("maintenance", help="perform maintenance (clean up)")
    # maintenance_parser.add_argument('maxfiles', help="Max number of statuscheck files to keep")
    # maintenance_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
    #                                 action="store_true")
    # maintenance_parser.add_argument('-t', '--test', help="don't delete anything, just test", default=False,
    #                                 action="store_true")

    mac_tracking_parser = mac_checks_parser.add_parser("mac_tracking",
                                                               help="search for a mac address (SNMP)")
    mac_tracking_parser.add_argument('-f', '--file', help="specify iplist file to use if not using default")
    mac_tracking_parser.add_argument('-e', '--email', help="specify which email to send file to")
    mac_tracking_parser.add_argument('-i', '--ignorefield', help="specify which field(s) to ignore if empty")
    mac_tracking_parser.add_argument('-n', '--numprocs', help="specify how many concurrent processes")
    mac_tracking_parser.add_argument('-p', '--parallel', help="run grab processes in parallel", default=False,
                                          action="store_true")
    mac_tracking_parser.add_argument('-l', '--limit', help="only put switches specified in iplist in summary file",
                                          default=False, action="store_true")
    mac_tracking_parser.add_argument('-c', '--check', help="Operate on existing database, do not search",
                                          default=False, action="store_true")
    mac_tracking_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                          action="store_true")
    mac_tracking_parser.add_argument('-d', '--debug', help="run in debug mode (extremely verbose)", default=False,
                                          action="store_true")
    mac_tracking_parser.add_argument('-m', '--maxentries', help="modify max number of historical entries")
    mac_tracking_parser.add_argument('-x', '--xecutive', help="print out a modified summary file", default=False,
                                          action="store_true")



    #Status Checking parsers
    status_checks_parser = subparsers.add_parser("status_checks", help="functions regarding checking the status of switches").add_subparsers(dest="status_checks")
    maintenance_parser = status_checks_parser.add_parser("maintenance",help="perform maintenance (clean up)")
    maintenance_parser.add_argument('maxfiles', help="Max number of statuscheck files to keep")
    maintenance_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                          action="store_true")
    maintenance_parser.add_argument('-t', '--test', help="don't delete anything, just test", default=False, action="store_true")

    activity_tracking_parser = status_checks_parser.add_parser("activity_tracking", help="check if port status has changed")
    activity_tracking_parser.add_argument('-f', '--file', help="specify iplist file to use if not using default")
    activity_tracking_parser.add_argument('-e', '--email', help="specify which email to send file to")
    activity_tracking_parser.add_argument('-i', '--ignorefield', help="specify which field(s) to ignore if empty")
    activity_tracking_parser.add_argument('-n', '--numprocs', help="specify how many concurrent processes")
    activity_tracking_parser.add_argument('-p', '--parallel', help="run grab processes in parallel", default=False,
                                          action="store_true")
    activity_tracking_parser.add_argument('-l', '--limit', help="only put switches specified in iplist in summary file",
                                          default=False, action="store_true")
    activity_tracking_parser.add_argument('-c', '--check', help="Operate on existing statcheck files, no log ins",
                                          default=False, action="store_true")
    activity_tracking_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                          action="store_true")
    activity_tracking_parser.add_argument('-d', '--debug', help="run in debug mode (extremely verbose)", default=False,
                                          action="store_true")
    activity_tracking_parser.add_argument('-m', '--maxentries', help="modify max number of historical entries")
    activity_tracking_parser.add_argument('-x', '--xecutive', help="print out a modified summary file", default=False,
                                          action="store_true")

    switch_check_parser = status_checks_parser.add_parser("switch_check", help="check switch info")
    switch_check_parser.add_argument('-i', '--ipaddr', metavar='IP', help='Switch Address interface is on')
    switch_check_parser.add_argument('-c', '--csv', help="save to a specified csv file")
    switch_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    switch_check_parser.add_argument('-d', '--debug', help="run in debug very verbose mode", default=False, action="store_true")
    switch_check_parser.add_argument('-l', '--load', help="load switchstruct from a specified file")
    switch_check_parser.add_argument('-r', '--ro', help="use a custom RO snmp string")
    switch_check_parser.add_argument('-e', '--email', help="email to send csv file to (ONLY with CSV option)")

    #DB commands - subset of status checking
    db_cmds_parser = subparsers.add_parser("database_commands",
                                                 help="functions simulating databases").add_subparsers(dest="database_commands")
    db_cmds_find_parser = db_cmds_parser.add_parser("find", help="search for items").add_subparsers(dest="find")
    db_cmds_find_desc_parser = db_cmds_find_parser.add_parser("desc", help="search for descriptions")
    db_cmds_find_desc_parser.add_argument('searchstring', help='text to search for')
    db_cmds_find_desc_parser.add_argument('-s', '--sensitive', help="search for string sensitive to case", default=False, action="store_true")
    db_cmds_find_desc_parser.add_argument('-e', '--exact', help="search for exact match", default=False, action="store_true")
    db_cmds_find_desc_parser.add_argument('-c', '--csv', help="Output as CSV", default=False,
                                          action="store_true")
    db_cmds_find_desc_parser.add_argument('-v', '--verbose', help="verbose output", default=False, action="store_true")
    db_cmds_find_desc_parser.add_argument('-f', '--file', help="Output to specific file")
    db_cmds_find_desc_parser.add_argument('-n', '--name', help=" name of switch to search (can be partial)")

    db_cmds_find_mac_parser = db_cmds_find_parser.add_parser("mac", help="search for macs")
    db_cmds_find_mac_parser.add_argument('searchstring', help='text to search for')
    db_cmds_find_mac_parser.add_argument('-v', '--verbose', help="verbose output", default=False, action="store_true")
    db_cmds_find_mac_parser.add_argument('-n', '--name', help=" name of switch to search (can be partial)")
    db_cmds_find_mac_parser.add_argument('-i', '--ipfile', help="file to grap IPs from if not default")

    #dbcmds reports
    db_cmds_reports_parser = db_cmds_parser.add_parser("reports", help="create various reports from statcheck files").add_subparsers(dest="reports")

    #dbcmds reports fmnet
    db_cmds_reports_fmnet_parser = db_cmds_reports_parser.add_parser("fmnet", help="reports for fmnet").add_subparsers(dest="fmnet")

    # dbcmds reports fmnet psviolations  TODO Change to an argument for email title and ignorefield flag to be more generic
    db_cmds_reports_fmnet_psviolations_parser = db_cmds_reports_fmnet_parser.add_parser("psviolations", help="report on port security violations")
    db_cmds_reports_fmnet_psviolations_parser.add_argument('-v', '--verbose', help="verbose output", default=False, action="store_true")
    db_cmds_reports_fmnet_psviolations_parser.add_argument('-f', '--file', help="limit processing to ips contained in file")
    db_cmds_reports_fmnet_psviolations_parser.add_argument('-d', '--debug', help="run in debug mode (extremely verbose)", default=False,
                  action="store_true")
    db_cmds_reports_fmnet_psviolations_parser.add_argument('-e', '--email', help="specify email to send file to")
    db_cmds_reports_fmnet_psviolations_parser.add_argument('-x', '--xecutive', help="print out a modified summary file", default=False,
                                          action="store_true")

    #Mapper Parser
    mapper_parser = subparsers.add_parser("mapper", help="functions to map out connections")
    mapper_parser.add_argument('filename', help="file containing ip address to map")
    mapper_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                    action="store_true")
    mapper_parser.add_argument('-t', '--test', help="don't delete anything, just test", default=False,
                                    action="store_true")
    mapper_parser.add_argument('-d', '--debug', help="run in debug mode (extremely verbose)", default=False,
                                          action="store_true")
    mapper_parser.add_argument('-e', '--email', help="specify email to send graph to")
    mapper_parser.add_argument('-r', '--remove', help="remove file afterwards", default=False,
                                      action="store_true")
    mapper_parser.add_argument('-c', '--customro', help="use custom RO string")
    mapper_parser.add_argument('-f', '--filterstring', help="strings to end on, ie:domain names", default="EMPTY_STRING")
    mapper_parser.add_argument('-m', '--multifilter', help="colon seperated strings to end on, ie:domain names",
                               default="EMPTY_STRING")


    #Tests Begin
    test_parser = subparsers.add_parser("test", help="various tests").add_subparsers(dest="test")
    command_blaster_parser = test_parser.add_parser("command_blaster", help="send some non-enabled commands")
    command_blaster_parser.add_argument('ipaddrfile', help='text file with switch addresses to run commands on')
    command_blaster_parser.add_argument('commandfile', help='text file with commands to run')
    command_blaster_parser.add_argument('-e', '--enable', help="run in enable mode", default=False,
                                         action="store_true")
    command_blaster_parser.add_argument('-t', '--timing', help="send commands in timing mode", default=False,
                                         action="store_true")
    command_blaster_parser.add_argument('-s', '--single', help="parses ipaddrfile as a single ip rather than file", default=False,
                                        action="store_true")
    command_blaster_parser.add_argument('-m', '--manual', help="specify manual fields in iplist", default=False,
                                         action="store_true")
    command_blaster_parser.add_argument('-v', '--verbose', help="verbose output", default=False,action="store_true")
    # command_blaster_parser.add_argument('-d', '--debug', help="debug output", default=False,action="store_true")

    error_counter_parser = test_parser.add_parser("error_counter", help="check the errors of an interface")
    error_counter_parser.add_argument('ipaddr', help='address of switch to check')
    error_counter_parser.add_argument('interface', help='string to grab error counts of example:8/10')
    error_counter_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    bad_phone_parser = test_parser.add_parser("bad_phone_check", help="look for bad phones")
    bad_phone_parser.add_argument('file', metavar='file',help='The file with IPs to check')
    bad_phone_parser.add_argument('-s', '--skip', help="skip verification", default=False, action="store_true")
    dell_snmp_parser = test_parser.add_parser("dellsnmp", help="add snmp ro string")
    dell_snmp_parser.add_argument('file', metavar='file', help='The file with IPs to check')
    dell_snmp_parser.add_argument('snmpstring', metavar='snmpstring', help="snmp string to add")

    snmpv3_parser = test_parser.add_parser("snmpv3", help="simple test out snmpv3")
    snmpv3_parser.add_argument('ipaddr', help='ip')
    snmpv3_parser.add_argument('snmpv3_user_string', help='snmp user string')
    snmpv3_parser.add_argument('snmpv3_auth_string', help='snmp auth string')
    snmpv3_parser.add_argument('oid', help='oid')

    connect_count_parser = test_parser.add_parser("connection_count", help="count not connected ports")
    connect_count_parser.add_argument('file', help='The file with IPs to check')

    batch_run_wrapper_parser = test_parser.add_parser("batch_command_wrapper", help="run batches of command line scripts")
    batch_run_wrapper_parser.add_argument('file', help='The file with cli commands to run')

    vlan_namer_parser = test_parser.add_parser('Vlan_Namer',help="Rename Vlans")
    vlan_namer_parser.add_argument('file', help='The file with IPs to verify vlan names upstream')
    vlan_namer_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    vlan_namer_parser.add_argument('-a', '--apply', help="apply changes", default=False, action="store_true")

    ipam_rest_parser = test_parser.add_parser("ipam_rest_test", help="rest command testing")
    ipam_rest_parser.add_argument('building', help='The 3 letter code of the building to grab vlans from')
    ipam_rest_parser.add_argument('vlanid', help='The vlan to get the name of')

    #Tests End


    # create subcategory for tools
    tools_parser = subparsers.add_parser("tools", help="various tools").add_subparsers(dest="tools")

    port_change_parser = tools_parser.add_parser("port_change", help="update a port")
    port_change_parser.add_argument('ipaddr', metavar='IP', help='Switch Address interface is on')
    port_change_parser.add_argument('interface', metavar='interface', help='interface to update')
    # vlan_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")


    # parser commands for ap_poke
    ap_poke_parser = tools_parser.add_parser("ap_poke", help="Toggle APs with issues")
    ap_poke_parser.add_argument('ipaddr', metavar='IP', help='Switch Address AP is on')
    ap_poke_parser.add_argument('interface', metavar='interface', help='interface AP is on')
    ap_poke_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    ap_poke_parser.add_argument('-s', '--skip', help="skip verification", default=False,action="store_true")
    ap_poke_parser.add_argument('-t', '--tdr', help="perform TDR test", default=False, action="store_true")
    ap_poke_parser.add_argument('-l', '--login', help="Ask for login credentials", default=False, action="store_true")

    #diggle functionality
    dig_tool_parser = tools_parser.add_parser("dig", help="List hostnames from dns by domain")
    dig_tool_parser.add_argument('domain', help='domain to do a zone transfer from')
    dig_tool_parser.add_argument('hoststring', help='things to match on for DNS names ie: switch-location-place')
    dig_tool_parser.add_argument('-a', '--advanced', help="Gather more info about hosts", default=False, action="store_true")

    #portlabel grab/send functionality
    port_label_tool_parser = tools_parser.add_parser("port_label", help="check for port label files in email")
    port_label_tool_parser.add_argument('-b', '--batch', help="skip verification with user, apply changes", default=False, action="store_true")
    port_label_tool_parser.add_argument('-n', '--notify', help="send email to submitter",default=False, action="store_true")
    port_label_tool_parser.add_argument('-v', '--verbose', help="Run with additional information", default=False, action="store_true")

    #standardizer
    standardize_tool_parser = tools_parser.add_parser("standardize", help="apply standard configurations")
    standardize_tool_parser.add_argument('ipfile', help='The file with IPs to verify vlan names upstream. Format IP,username,Password')
    standardize_tool_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False, action="store_true")
    standardize_tool_parser.add_argument('-a', '--apply', help="apply changes", default=False, action="store_true")
    standardize_tool_parser.add_argument('-m', '--manual', help="IP list file will specify vendors and login creds", default=False, action="store_true")
    standardize_tool_parser.add_argument('-c', '--cmdfile', help="custom file with standard configs if not default")

    #passchanger
    # standardizer
    passchanger_tool_parser = tools_parser.add_parser("hp_password_change", help="change local passwords on hp switches")
    passchanger_tool_parser.add_argument('ipfile',
                                         help='The file with IPs to verify vlan names upstream. Format IP,username,Password')
    passchanger_tool_parser.add_argument('username',help='new username to set as manager')
    passchanger_tool_parser.add_argument('password', help='new password to set as manager')

    passchanger_tool_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")
    passchanger_tool_parser.add_argument('-a', '--apply', help="apply changes", default=False, action="store_true")
    passchanger_tool_parser.add_argument('-m', '--manual', help="IP list file will specify vendors and login creds",
                                         default=False, action="store_true")

    #arp_table check
    arp_table_check_parser = tools_parser.add_parser("arp_table_check", help="check the arp table of a switch")
    arp_table_check_parser.add_argument('ipaddr', help='switch to check')
    arp_table_check_parser.add_argument('cmdfile', help='file that contains arp filters')
    arp_table_check_parser.add_argument('-f', '--filter', help="filter out lines containing csv filter val")
    arp_table_check_parser.add_argument('-c', '--csv', help="output to screen as csv", default=False,
                                         action="store_true")
    arp_table_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")

    #mac table check (could be replaced with command_blaster)
    mac_table_check_parser = tools_parser.add_parser("mac_table_check", help="check the mac table of switches")
    mac_table_check_parser.add_argument('ipfile', help='file containing switch ips to check')
    mac_table_check_parser.add_argument('-f', '--filter', help="filter out lines containing csv filter val")
    mac_table_check_parser.add_argument('-c', '--csv', help="output to screen as csv", default=False,
                                         action="store_true")

    mac_table_check_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                                         action="store_true")

    # create subcategory for archival
    archival_parser = subparsers.add_parser("archival", help="archival commands").add_subparsers(dest="archival")
    archival_basic_parser = archival_parser.add_parser("basic_archival", help="simple backup of legacy files")
    archival_basic_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                               action="store_true")
    archival_basic_parser.add_argument('-d', '--debug', help="run in debug mode (extremely verbose)", default=False,
                               action="store_true")
    archival_basic_parser.add_argument('-e', '--email', help="specify email to send graph to")
    archival_basic_parser.add_argument('-r', '--remove', help="remove file afterwards", default=False,
                               action="store_true")
    archival_basic_parser.add_argument('-m', '--maintenance', help="perform maintenance after running, removing specified number of files")

    archival_basic_maintenance_parser = archival_parser.add_parser("basic_archival_maintenance", help="simple backup maintenance")
    archival_basic_maintenance_parser.add_argument('-v', '--verbose', help="run in verbose mode", default=False,
                               action="store_true")
    archival_basic_maintenance_parser.add_argument('-d', '--debug', help="run in debug mode (extremely verbose)", default=False,
                               action="store_true")
    archival_basic_maintenance_parser.add_argument('maxfiles',  help="how many backup files to keep")
    archival_basic_maintenance_parser.add_argument('-c', '--check', help="do not remove any files", default=False,action="store_true")


    archival_test_parser = archival_parser.add_parser("archival_test", help="test svn")
    # archival_test_parser.add_argument('ipaddr', metavar='IP', help='Switch Address interface is on')
    # archival_test_parser.add_argument('interface', metavar='interface', help='interface to update')





    argcomplete.autocomplete(parser)
    cmdargs = parser.parse_args()

#change these to only creating if required
    macsearcher = Lefty(cmdargs,config)
    hostnamer = HostNamer(cmdargs,config)
    upgradeCheck = Check(cmdargs, config)
    statusChecks = StatusChecks(cmdargs,config)
    mactracker = MacTracking(cmdargs, config)
    mapper = Mapper(cmdargs,config)
    tools = Tools(cmdargs, config)
    dbcmds = DBcmds(cmdargs,config)
    archivist = Archivist(cmdargs,config)
    # functions = Functions(cmdargs,config)
    # snmpFuncs = SnmpFuncs(cmdargs,config)
    test = Test(cmdargs, config)


    ### complete CLI Parsing

    #create the loop for interactive prompt

    if cmdargs.maincommand == "mac_search":
        if cmdargs.mac_search == 'single' or cmdargs.mac_search == 'batch':
            macsearcher.begin_search()
        elif cmdargs.mac_search =='general':
            macsearcher.begin_snmp_search()
    elif cmdargs.maincommand == "hostname_update":
        hostnamer.hostname_update()
    # elif args.direct == "SNMPTest":
    #     hostnamer.snmp_test(args.ipaddr, config, args.oid)
    elif cmdargs.maincommand == "write_test":
        #hostnamer.write_test(cmdargs.ipaddr, config)
        hostnamer.subs.snmp_save_config(cmdargs.ipaddr)
    elif cmdargs.maincommand == "bulk_vlan_change":
        hostnamer.bulk_vlan_change(cmdargs.ipaddr,cmdargs.oldvlan,int(cmdargs.newvlan))
    elif cmdargs.maincommand == "upgrade_check":
        upgradeCheck.begin()

    elif cmdargs.maincommand == "tools":
        if cmdargs.tools == 'ap_poke':
            try:  #<TODO ADD THIS FUNCTIONALITY EVERYWHERE>
                tools.ap_poke()
            except SystemExit as errcode:
                sys.exit(errcode)
        elif cmdargs.tools == 'port_change':
            tools.change_port_vlan()
        elif cmdargs.tools =='dig':
            tools.diggle()
        elif cmdargs.tools =='port_label':
            tools.port_label_check()
        elif cmdargs.tools =='standardize':
            tools.standardize_begin()
        elif cmdargs.tools =='hp_password_change':
            tools.hp_password_change_begin()
        elif cmdargs.tools =='arp_table_check':
            tools.arp_table_check()
        elif cmdargs.tools =='mac_table_check':
            tools.mac_table_check()
    elif cmdargs.maincommand == 'status_checks':
        if cmdargs.status_checks == "activity_tracking":
            statusChecks.activity_tracking_begin()
        elif cmdargs.status_checks == "switch_check":
            statusChecks.switch_check()
        elif cmdargs.status_checks == "maintenance":
            try:
                statusChecks.Maintenance(int(cmdargs.maxfiles))
            except ValueError:
                print("maxfiles is not a number, exiting")
    elif cmdargs.maincommand == 'mac_checks':
        if cmdargs.mac_checks == "mac_tracking":
            mactracker.mac_tracking_begin()
    elif cmdargs.maincommand == 'database_commands':
        if cmdargs.database_commands == 'find':
            if cmdargs.find == 'desc':
                dbcmds.find_description()
            elif cmdargs.find == 'mac':
                dbcmds.find_mac_address()
        if cmdargs.database_commands =='reports':
            if cmdargs.reports == 'fmnet':
                if cmdargs.fmnet == 'psviolations':
                    dbcmds.create_port_security_report();
    elif cmdargs.maincommand == 'mapper':
            mapper.iterate()
    elif cmdargs.maincommand == 'test':
        if cmdargs.test == 'command_blaster':
            test.command_blaster_begin()
        elif cmdargs.test == 'error_counter':
            test.error_check()
        elif cmdargs.test == 'bad_phone_check':
            test.bad_phone_search_begin()
        elif cmdargs.test == "dellsnmp":
            test.dell_snmp_Begin()
        elif cmdargs.test == "connection_count":
            test.connection_count_begin()
        elif cmdargs.test == "batch_command_wrapper":
            test.batch_command_wrapper()
        elif cmdargs.test == "Vlan_Namer":
            test.vlan_namer_begin()
        elif cmdargs.test == "snmpv3":
            test.subs.test_snmpv3(cmdargs.ipaddr,cmdargs.oid,snmpv3_user_string=cmdargs.snmpv3_user_string, snmpv3_auth_string=cmdargs.snmpv3_auth_string)
        elif cmdargs.test == "ipam_rest_test":
            temp = test.Ipam_Rest_Get("https://ipam.ualberta.ca/solid.intranet/rest/vlmvlan_list",
                                                   {"WHERE": "vlmdomain_description like '{}' and vlmvlan_vlan_id = '{}'".format(cmdargs.building,cmdargs.vlanid)})
            print(temp)
    elif cmdargs.maincommand == 'archival':
        if cmdargs.archival == 'basic_archival':
            archivist.basic_archival()
        elif cmdargs.archival == 'basic_archival_maintenance':
            try:
                archivist.basic_maintenance(int(cmdargs.maxfiles))
            except ValueError:
                print("maxfiles is not a number, exiting")







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