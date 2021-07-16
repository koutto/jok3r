#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Db Controller
###
import os
import sys
import cmd2
import argparse
from glob import glob

from lib.controller.Controller import Controller
from lib.core.Config import *
from lib.core.Constants import *
from lib.core.Exceptions import FilterException
from lib.core.Target import Target
from lib.importer.NmapResultsParser import NmapResultsParser
from lib.importer.ShodanResultsParser import ShodanResultsParser
from lib.utils.ArgParseUtils import *
from lib.utils.FileUtils import FileUtils
from lib.utils.NetUtils import NetUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Mission import Mission
from lib.reporter.Reporter import Reporter
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.CommandOutputsRequester import CommandOutputsRequester
from lib.requester.CredentialsRequester import CredentialsRequester
from lib.requester.HostsRequester import HostsRequester
from lib.requester.MissionsRequester import MissionsRequester
from lib.requester.OptionsRequester import OptionsRequester
from lib.requester.ProductsRequester import ProductsRequester
from lib.requester.ResultsRequester import ResultsRequester
from lib.requester.ServicesRequester import ServicesRequester
from lib.requester.VulnsRequester import VulnsRequester
from lib.output.Logger import logger
from lib.output.Output import Output
from apikeys import API_KEYS


class DbController(cmd2.Cmd):

    # Command categories
    CMD_CAT_MISSION_SCOPE = 'Missions data'
    CMD_CAT_IMPORT        = 'Import'
    CMD_CAT_RESULTS       = 'Attacks results'
    CMD_CAT_REPORTING     = 'Reporting'

    intro = DB_INTRO
    formatter_class = lambda prog: LineWrapRawTextHelpFormatter(
        prog, max_help_position=ARGPARSE_MAX_HELP_POS)


    def __init__(self, arguments, settings, sqlsession):
        self.arguments = arguments
        self.settings  = settings
        self.sqlsess   = sqlsession

        super().__init__(persistent_history_file=DB_HIST_FILE, 
                         persistent_history_length=500)

        #self.cmdqueue.append('alias help "help -v"')
        self.allow_cli_args = False

        # Delete useless cmd2 built-in commands
        del cmd2.Cmd.do_edit
        #del cmd2.Cmd.do_load
        del cmd2.Cmd.do_py
        #del cmd2.Cmd.do_pyscript
        #del cmd2.Cmd.do_set 
        del cmd2.Cmd.do_shortcuts

        self.current_mission = 'default'
        self.change_current_mission('default')


    def run(self):
        self.cmdloop()


    def change_current_mission(self, name, verbose=False):
        mission = self.sqlsess.query(Mission).filter(Mission.name == name).first()
        if not mission:
            logger.error('No mission with this name')
        else:
            self.current_mission = name
            self.prompt = Output.colored('jok3rdb', color='light_green', attrs='bold')+ \
                Output.colored('[{}]'.format(name), color='light_blue', attrs='bold') + \
                Output.colored('> ', color='light_green', attrs='bold')

            if verbose: 
                logger.info('Selected mission is now {name}'.format(name=name))


    @cmd2.with_argument_list
    def do_help(self, args):
        """Display this help message"""
        super().do_help('-v' if not args else args)


    #------------------------------------------------------------------------------------
    # Missions Management

    mission = argparse.ArgumentParser(
        description='Manage missions', 
        formatter_class=formatter_class)

    mission_mxg = mission.add_mutually_exclusive_group()
    mission_mxg.add_argument(
        '-a', '--add', 
        action  = 'store', 
        metavar = '<name>', 
        help    = 'Add mission')
    mission_mxg.add_argument(
        '-c', '--comment', 
        nargs   = 2, 
        metavar = ('<name>','<comment>'), 
        help    = 'Change the comment of a mission')
    mission_mxg.add_argument(
        '-d', '--del', 
        action  = 'store', 
        dest    = 'delete', 
        metavar = '<name>', 
        help    = 'Delete mission')
    mission_mxg.add_argument(
        '-D', '--reset', 
        action  = 'store_true', 
        help    = 'Delete all missions')
    mission_mxg.add_argument(
        '-r', '--rename', 
        nargs   = 2, 
        metavar = ('<old>','<new>'), 
        help    = 'Rename mission')
    mission_mxg.add_argument(
        '-S', '--search', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Search string to filter by')
    mission_mxg.add_argument(
        'name', 
        nargs   = '?', 
        metavar = '<name>', 
        help    = 'Switch mission')

    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(mission)
    def do_mission(self, args):
        """Missions management"""
        print()

        req = MissionsRequester(self.sqlsess)

        # --add <name>
        if args.add:
            if req.add(args.add):
                self.change_current_mission(args.add, verbose=True)

        # --comment <name> <comment>
        elif args.comment:
            req.add_filter(Condition(args.comment[0], FilterData.MISSION_EXACT))
            req.edit_comment(args.comment[1])

        # --del <name>
        elif args.delete:
            req.add_filter(Condition(args.delete, FilterData.MISSION_EXACT))
            req.delete()
            if args.delete == self.current_mission:
                self.change_current_mission('default')   

        # --reset     
        elif args.reset:
            if Output.prompt_confirm(
                'Are you sure you want to delete all missions ?', default=False):
                req.reset()

        # --rename <old> <new>
        elif args.rename:
            status = req.rename(args.rename[0], args.rename[1])
            if status is True and args.rename[0] == self.current_mission:
                self.change_current_mission(args.rename[1])

        # --search <string>
        elif args.search:
            filter_ = Filter()
            filter_.add_condition(Condition(args.search, FilterData.MISSION))
            filter_.add_condition(Condition(args.search, FilterData.COMMENT_MISSION))
            req.add_filter(filter_)
            req.show(self.current_mission)

        # <name> (mission name)
        elif args.name:
            self.change_current_mission(args.name, verbose=True)

        else:
            print('All available missions:')
            req.show(self.current_mission)

        print()

    def complete_mission(self, text, line, begidx, endidx):
        """Complete with mission name"""
        missions = MissionsRequester(self.sqlsess).get_list_mission_names()
        flag_dict = {
            '-c'        : missions,
            '--comment' : missions,
            '-d'        : missions,
            '--del'     : missions,
            '-r'        : missions,
            '--rename'  : missions,
            'mission'   : missions,
        }

        return self.flag_based_complete(text, line, begidx, endidx, flag_dict=flag_dict)


    #------------------------------------------------------------------------------------
    # Hosts Management

    hosts = argparse.ArgumentParser(
        description='Hosts in the current mission scope', 
        formatter_class=formatter_class)

    hosts_manage = hosts.add_argument_group('Manage hosts').add_mutually_exclusive_group()
    hosts_manage.add_argument(
        '-c', '--comment', 
        action  = 'store', 
        metavar = '<comment>', 
        help    = 'Change the comment of selected host(s)')
    hosts_manage.add_argument(
        '-d', '--del', 
        action  = 'store_true', 
        dest    = 'delete', 
        help    = 'Delete selected host(s) (instead of displaying)')

    hosts_filters = hosts.add_argument_group('Filter hosts')
    hosts_filters.add_argument(
        '-o', '--order', 
        action  = 'store', 
        metavar = '<column>', 
        help    = 'Order rows by specified column')
    hosts_filters.add_argument(
        '-S', '--search', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Search string to filter by')
    hosts_filters.add_argument(
        'addrs', 
        nargs   = '*', 
        metavar = '<addr1> <addr2> ...', 
        help    = 'IPs/CIDR ranges/hostnames to select')

    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(hosts)
    def do_hosts(self, args):
        """Hosts in the current mission scope"""
        print()
        req = HostsRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Filtering options:
        # ------------------
        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)

        if args.addrs:
            filter_addrs = Filter(FilterOperator.OR)
            for addr in args.addrs:
                if NetUtils.is_valid_ip(addr) or NetUtils.is_valid_ip_range(addr):
                    filter_addrs.add_condition(Condition(addr, FilterData.IP))
                else:
                    filter_addrs.add_condition(Condition(addr, FilterData.HOST))
            filter_.add_condition(filter_addrs)

        # --search <string>
        if args.search:
            filter_search = Filter(FilterOperator.OR)
            filter_search.add_condition(Condition(args.search, FilterData.HOST))
            filter_search.add_condition(Condition(args.search, FilterData.OS))
            filter_search.add_condition(Condition(args.search, FilterData.COMMENT_HOST))
            filter_.add_condition(filter_search)

        # --order <column>
        if args.order:
            req.order_by(args.order)

        try:
            req.add_filter(filter_)
        except FilterException as e:
            logger.error(e)
            print()
            return

        # Operations:
        # ----------
        # Edit comment : --comment <comment>
        if args.comment:
            if not req.filter_applied:
                if not self.__confirm_for_all('edit comment for ALL hosts'):
                    return
            req.edit_comment(args.comment)

        # Delete : --del 
        elif args.delete:
            if not req.filter_applied:
                if not self.__confirm_for_all('delete ALL hosts and related services'):
                    return
            req.delete()

        # Display (default)
        else:
            req.show()

        print()


    #------------------------------------------------------------------------------------
    # Services Management

    services = argparse.ArgumentParser(
        description='Services in the current mission scope', 
        formatter_class=formatter_class)

    services_manage = services.add_argument_group('Manage services')\
        .add_mutually_exclusive_group()
    services_manage.add_argument(
        '-a', '--add', 
        action  = 'store', 
        nargs   = 3, 
        metavar = ('<host>','<port>','<service>'), 
        help    = 'Add a new service')
    services_manage.add_argument(
        '-u', '--url', 
        action  = 'store', 
        metavar = '<url>', 
        help    = 'Add a new URL')
    services_manage.add_argument(
        '-d', '--del', 
        action  = 'store_true', 
        dest    = 'delete', 
        help    = 'Delete selected service(s) (instead of displaying)')
    services_manage.add_argument(
        '-c', '--comment', 
        action  = 'store', 
        metavar = '<comment>', 
        help    = 'Change the comment of selected service(s)')
    services_manage.add_argument(
        '--https', 
        action  = 'store_true', 
        help    = 'Switch between HTTPS and HTTP protocol for URL of ' \
            'selected service(s)')

    services_creds = services.add_argument_group('Manage services credentials')\
        .add_mutually_exclusive_group()
    services_creds.add_argument(
        '--addcred', 
        action  = 'store', 
        nargs   = 2, 
        metavar = ('<user>','<pass>'), 
        help    = 'Add new credentials (username+password) for selected service(s)')
    services_creds.add_argument(
        '--addcred-http', 
        action  = 'store', 
        nargs   = 3, 
        metavar = ('<user>','<pass>','<auth-type>'), 
        help    = 'Add new credentials (username+password) for the specified ' \
            'authentication type on selected HTTP service(s)')
    services_creds.add_argument(
        '--adduser', 
        action  = 'store', 
        nargs   = 1, 
        metavar = ('<user>'), 
        help    = 'Add new username (password unknown) for selected service(s)')
    services_creds.add_argument(
        '--adduser-http', 
        action  = 'store', 
        nargs   = 2, 
        metavar = ('<user>','<auth-type>'), 
        help    = 'Add new username (password unknown) for the specified ' \
            'authentication type on selected HTTP service(s)')
    
    services_filters = services.add_argument_group('Filter services')
    services_filters.add_argument(
        '-H', '--hostname', 
        action  = 'store', 
        metavar = '<hostname1,hostname2...>', 
        help    = 'Search for a list of hostnames (comma-separated)')
    services_filters.add_argument(
        '-I', '--ip', 
        action  = 'store', 
        metavar = '<ip1,ip2...>', 
        help    = 'Search for a list of IPs (single IP/CIDR range comma-separated)')
    services_filters.add_argument(
        '-p', '--port', 
        action  = 'store', 
        metavar = '<port1,port2...>', 
        help    = 'Search for a list of ports (single/range comma-separated)')   
    services_filters.add_argument(
        '-r', '--proto', 
        action  = 'store', 
        metavar = '<protocol>', 
        help    = 'Only show [tcp|udp] services')
    services_filters.add_argument(
        '-U', '--up', 
        action  = 'store_true', 
        help    = 'Only show services which are up')
    services_filters.add_argument(
        '-o', '--order', 
        action  = 'store', 
        metavar = '<column>', 
        help    = 'Order rows by specified column')
    services_filters.add_argument(
        '-S', '--search', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Search string to filter by')
    services_filters.add_argument(
        'names', 
        nargs   = '*', 
        metavar = '<name1> <name2> ...', 
        help    = 'Services to select')


    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(services)
    def do_services(self, args):
        """Services in the current mission scope"""

        print()
        req = ServicesRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Filtering options:
        # ------------------
        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)

        # Service names
        if args.names:
            for n in args.names:
                if not self.settings.services.is_service_supported(n, multi=False):
                    logger.error('Service {name} is not valid/supported'.format(
                        name=n.lower()))
                    print()
                    return
            filter_.add_condition(Condition(args.names, FilterData.SERVICE_EXACT))

        # --order <column>
        if args.order:
            req.order_by(args.order)

        # --hostname <hostname1,hostname2...>
        if args.hostname:
            # OR between submitted hostnames
            filter_.add_condition(Condition(args.hostname.split(','), FilterData.HOST))

        # --ip <ip1,ip2...>
        if args.ip:
            # OR between submitted ips/ranges
            filter_.add_condition(Condition(args.ip.split(','), FilterData.IP))

        # --port <port1,port2...>
        if args.port:
            # OR between ports/port-ranges
            filter_.add_condition(Condition(args.port.split(','), FilterData.PORT))

        # --proto <protocol>
        if args.proto:
            filter_.add_condition(Condition(args.proto, FilterData.PROTOCOL))

        # --up
        if args.up:
            filter_.add_condition(Condition(args.up, FilterData.UP))

        # --search <string>
        if args.search:
            filter_search = Filter(FilterOperator.OR)
            filter_search.add_condition(Condition(args.search, FilterData.HOST))
            filter_search.add_condition(Condition(args.search, FilterData.BANNER))
            filter_search.add_condition(Condition(args.search, FilterData.URL))
            filter_search.add_condition(Condition(args.search, FilterData.HTML_TITLE))
            filter_search.add_condition(Condition(args.search, 
                FilterData.COMMENT_SERVICE))
            filter_.add_condition(filter_search)

        try:
            req.add_filter(filter_)
        except FilterException as e:
            logger.error(e)
            print()
            return

        # Operations:
        # -----------
        # --add <host> <port> <service>'
        if args.add:
            host, port, service = args.add

            if not NetUtils.is_valid_port(port):
                logger.error('Port is invalid, not in range [0-65535]')
            elif not self.settings.services.is_service_supported(service, multi=False):
                logger.error('Service {name} is not valid/supported'.format(
                    name=service.lower()))
            else:
                req.add_service(
                    host, 
                    port, 
                    self.settings.services.get_protocol(service), 
                    service, 
                    self.settings.services,
                    nmap_banner_grabbing=True,
                    reverse_dns_lookup=True, 
                    availability_check=True,
                    html_title_grabbing=True,
                    web_technos_detection=True)

        # --url <url>
        elif args.url:
            args.url = WebUtils.add_prefix_http(args.url)
            if not WebUtils.is_valid_url(args.url):
                logger.error('URL is invalid')
            else:
                req.add_url(
                    args.url, 
                    self.settings.services,
                    reverse_dns_lookup=True,
                    availability_check=True,
                    nmap_banner_grabbing=True,
                    html_title_grabbing=True,
                    web_technos_detection=True)
        # --del
        elif args.delete:
            if not req.filter_applied:
                if not self.__confirm_for_all('delete ALL services'):
                    return
            req.delete()

        # --comment <comment>
        elif args.comment:
            if not req.filter_applied:
                if not self.__confirm_for_all('edit comment for ALL services'):
                    return
            req.edit_comment(args.comment)


        # --https
        elif args.https:
            if not req.filter_applied:
                if not self.__confirm_for_all('apply switch for ALL URLs'):
                    return
            req.switch_https()      

        # --addcred <user> <pass>   
        elif args.addcred:
            if not req.filter_applied:
                if not self.__confirm_for_all('add same creds for ALL services'):
                    return

            req.add_cred(username=args.addcred[0], 
                         password=args.addcred[1], 
                         auth_type=None) 

        # --addcred-http <user> <pass> <auth-type>
        elif args.addcred_http:
            if not req.are_only_http_services_selected():
                logger.warning('Some non-HTTP services are selected. Use --addcred ' \
                    'instead for non-HTTP services')
                print()
                return
            if not self.settings.services.is_valid_auth_type(args.addcred_http[2]):
                logger.warning('Invalid HTTP authentication type')
                logger.info('List of supported authentication types: ')
                for auth_type in self.settings.services.get_authentication_types('http'):
                    logger.info('- {type}'.format(type=auth_type))
                return
            if not req.filter_applied:
                if not self.__confirm_for_all('add same creds for ALL HTTP services'):
                    return
            req.add_cred(username=args.addcred_http[0], 
                         password=args.addcred_http[1], 
                         auth_type=args.addcred_http[2]) 

        # --adduser <user>
        elif args.adduser:
            if not req.filter_applied:
                if not self.__confirm_for_all('add same username for ALL services'):
                    return

            req.add_cred(username=args.adduser[0], 
                         password=None, 
                         auth_type=None)

        # --adduser-http <user> <auth-type>
        elif args.adduser_http:
            if not req.are_only_http_services_selected():
                logger.warning('Some non-HTTP services are selected. Use --adduser ' \
                    'instead for non-HTTP services')
                print()
                return
            if not self.settings.services.is_valid_auth_type(args.adduser_http[1]):
                logger.warning('Invalid HTTP authentication type')
                logger.info('List of supported authentication types: ')
                for auth_type in self.settings.services.get_authentication_types('http'):
                    logger.info('- {type}'.format(type=auth_type))
                print()
                return
            if not req.filter_applied:
                if not self.__confirm_for_all('add same username for ALL HTTP services'):
                    return

            req.add_cred(username=args.adduser_http[0], 
                         password=None, 
                         auth_type=args.adduser_http[1]) 

        # Display (default)
        else:
            req.show()                      

        print()


    #------------------------------------------------------------------------------------
    # Creds Management

    creds = argparse.ArgumentParser(
        description='Credentials in the current mission scope', 
        formatter_class=formatter_class,
        epilog='Note: you can also use "services --addcred/--addonlyuser" to add ' \
            'new creds')

    creds_manage = creds.add_argument_group('Manage credentials')\
        .add_mutually_exclusive_group()
    creds_manage.add_argument(
        '--addcred', 
        action  = 'store', 
        nargs   = 3, 
        metavar = ('<service-id>','<user>','<pass>'), 
        help    = 'Add new credentials (username+password) for the given service')
    creds_manage.add_argument(
        '--addcred-http', 
        action  = 'store', 
        nargs   = 4, 
        metavar = ('<service-id>','<user>','<pass>','<auth-type>'), 
        help    = 'Add new credentials (username+password) for the specified ' \
            'authentication type on HTTP service')
    creds_manage.add_argument(
        '--adduser', 
        action  = 'store', 
        nargs   = 2, 
        metavar = ('<service-id>','<user>'), 
        help    = 'Add new username (password unknown) for the given service')
    creds_manage.add_argument(
        '--adduser-http', 
        action  = 'store', 
        nargs   = 3, 
        metavar = ('<service-id>','<user>','<auth-type>'), 
        help    = 'Add new username (password unknown) for the specified ' \
            'authentication type on HTTP service')
    creds_manage.add_argument(
        '-c', '--comment', 
        action  = 'store', 
        metavar = '<comment>', 
        help    = 'Change the comment of selected cred(s)')
    creds_manage.add_argument(
        '-d', '--del', 
        action  = 'store_true', 
        dest    = 'delete', 
        help    = 'Delete selected credential(s) (instead of displaying)')
    
    creds_filters = creds.add_argument_group('Filter credentials')
    creds_filters.add_argument(
        '-U', '--username', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Select creds with username matching this string')
    creds_filters.add_argument(
        '-P', '--password', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Select creds with password matching this string')
    creds_filters_mxg = creds_filters.add_mutually_exclusive_group()
    creds_filters_mxg.add_argument(
        '-b', '--both', 
        action  = 'store_true', 
        help    = 'Select creds where username and password are both set ' \
            '(no single username)')
    creds_filters_mxg.add_argument(
        '-u', '--onlyuser', 
        action  = 'store_true', 
        help    = 'Select creds where only username is set')
    creds_filters.add_argument(
        '-H', '--hostname', 
        action  = 'store',
        metavar = '<hostname1,hostname2...>', 
        help    = 'Select creds for a list of hostnames (comma-separated)')
    creds_filters.add_argument(
        '-I', '--ip', 
        action  = 'store', 
        metavar = '<ip1,ip2...>', 
        help='Select creds for a list of IPs (single IP/CIDR range comma-separated)')
    creds_filters.add_argument(
        '-p', '--port', 
        action  = 'store', 
        metavar = '<port1,port2...>', 
        help    = 'Select creds a list of ports (single/range comma-separated)')   
    creds_filters.add_argument(
        '-s', '--service', 
        action  = 'store', 
        metavar = '<svc1,svc2...>', 
        help    = 'Select creds for a list of services (comma-separated)')
    creds_filters.add_argument(
        '-o', '--order', 
        action  = 'store', 
        metavar = '<column>', 
        help    = 'Order rows by specified column')
    creds_filters.add_argument(
        '-S', '--search', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Search string to filter by')


    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(creds)
    def do_creds(self, args):
        """Credentials in the current mission scope"""

        print()
        req = CredentialsRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Filtering options:
        # ------------------
        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)

        # --username <string>
        if args.username:
            filter_.add_condition(Condition(args.username, FilterData.USERNAME))
        
        # --password <string>
        if args.password:
            filter_.add_condition(Condition(args.password, FilterData.PASSWORD))
        
        # --both
        if args.both:
            filter_.add_condition(Condition(args.both, FilterData.USER_AND_PASS))

        # --onlyuser
        elif args.onlyuser:
            filter_.add_condition(Condition(args.onlyuser, FilterData.ONLY_USER))

        # --hostname <hostname1,hostname2...>
        if args.hostname:
            # OR between submitted hostnames
            filter_.add_condition(Condition(args.hostname.split(','), FilterData.HOST))

        # --ip <ip1,ip2...>
        if args.ip:
            # OR between submitted ips/ranges
            filter_.add_condition(Condition(args.ip.split(','), FilterData.IP))
        
        # --port <port1,port2...>
        if args.port:
            # OR between ports/port-ranges
            filter_.add_condition(Condition(args.port.split(','), FilterData.PORT))

        # --service <svc1,svc2...>
        if args.service:
            for s in args.service.split(','):
                if not self.settings.services.is_service_supported(s, multi=False):
                    logger.error('Service {name} is not valid/supported'.format(
                        name=s.lower()))
                    print()
                    return
            filter_.add_condition(Condition(args.service.split(','), 
                FilterData.SERVICE_EXACT))
        
        # --order <column>
        if args.order:
            req.order_by(args.order)

        # --search <string>
        if args.search:
            filter_search = Filter(FilterOperator.OR)
            filter_search.add_condition(Condition(args.search, FilterData.HOST))
            filter_search.add_condition(Condition(args.search, FilterData.AUTH_TYPE))
            filter_search.add_condition(Condition(args.search, FilterData.USERNAME))
            filter_search.add_condition(Condition(args.search, FilterData.PASSWORD))
            filter_search.add_condition(Condition(args.search, FilterData.URL))
            filter_search.add_condition(Condition(args.search, FilterData.COMMENT_CRED))
            filter_.add_condition(filter_search)
        try:
            req.add_filter(filter_)
        except FilterException as e:
            logger.error(e)
            print()
            return

        # Operations:
        # -----------
        add = args.addcred or args.addcred_http or args.adduser or args.adduser_http
        if add:
            try:
                service_id = int(add[0])
            except:
                logger.error('Invalid service id')
                return

            # --addcred <service-id> <user> <pass>
            if args.addcred:
                req.add_cred(service_id=service_id, 
                             username=args.addcred[1], 
                             password=args.addcred[2], 
                             auth_type=None)

            # --addcred-http <service-id> <user> <pass> <auth-type>
            elif args.addcred_http:
                if not self.settings.services.is_valid_auth_type(args.addcred_http[3]):
                    logger.warning('Invalid HTTP authentication type')
                    logger.info('List of supported authentication types: ')
                    for auth_type in self.settings.services\
                            .get_authentication_types('http'):
                        logger.info('- {type}'.format(type=auth_type))
                    print()
                    return
                req.add_cred(service_id=service_id, 
                             username=args.addcred_http[1], 
                             password=args.addcred_http[2], 
                             auth_type=args.addcred_http[3])

            # --adduser <service-id> <user>
            elif args.adduser:
                req.add_cred(service_id, args.adduser[1], None, None)

            # --adduser-http <service-id> <user> <auth-type>
            elif args.adduser_http:
                if not self.settings.services.is_valid_auth_type(args.adduser_http[2]):
                    logger.warning('Invalid HTTP authentication type')
                    logger.info('List of supported authentication types: ')
                    for auth_type in self.settings.services\
                            .get_authentication_types('http'):
                        logger.info('- {type}'.format(type=auth_type))
                    print()
                    return
                req.add_cred(service_id=service_id, 
                             username=args.adduser_http[1], 
                             password=None, 
                             auth_type=args.adduser_http[2])

        # --comment <comment>
        elif args.comment:
            if not req.filter_applied:
                if not self.__confirm_for_all('edit comment for ALL creds'):
                    return

            req.edit_comment(args.comment)

        # --del
        elif args.delete:
            if not req.filter_applied:
                if not self.__confirm_for_all('delete ALL creds'):
                    return
            req.delete()

        # Display (default)
        else:
            # --order <column>
            if not args.order:
                req.order_by('ip')
            req.show()

        print()


    #------------------------------------------------------------------------------------
    # Specific Options Management

    options = argparse.ArgumentParser(
        description='Specific Options in the current mission scope', 
        formatter_class=formatter_class)

    options_filters = options.add_argument_group('Filter options')
    options_filters.add_argument(
        '-I', '--ip', 
        action  = 'store', 
        metavar = '<ip1,ip2...>', 
        help    = 'Search for a list of IPs (single IP/CIDR range comma-separated)')
    options_filters.add_argument(
        '-H', '--hostname', 
        action  = 'store', 
        metavar = '<hostname1,hostname2...>', 
        help    = 'Search for a list of hostnames (comma-separated)')
    options_filters.add_argument(
        '-s', '--service', 
        action  = 'store', 
        metavar = '<service1,service2...>', 
        help    = 'Services to select')
    options_filters.add_argument(
        '-p', '--port', 
        action  = 'store', 
        metavar = '<port1,port2...>', 
        help    = 'Search for a list of ports (single/range comma-separated)')   
    options_filters.add_argument(
        '-r', '--proto', 
        action  = 'store', 
        metavar = '<protocol>', 
        help    = 'Only show [tcp|udp] services')
    options_filters.add_argument(
        '-S', '--search', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Search string to filter by')
    options_filters.add_argument(
        '-o', '--order', 
        action  = 'store', 
        metavar = '<column>', 
        help    = 'Order rows by specified column')
    options_filters.add_argument(
        'names', 
        nargs   = '*', 
        metavar = '<option_name1> <option_name2> ...', 
        help    = 'Option names to select')

    options_manage = options.add_argument_group('Manage options')
    options_manage.add_argument(
        '-d', '--del', 
        action  = 'store_true', 
        dest    = 'delete', 
        help    = 'Delete selected option(s) (instead of displaying)')


    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(options)
    def do_options(self, args):
        """Options in the current mission scope"""

        print()
        req = OptionsRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Filtering options:
        # ------------------
        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)

        # --ip <ip1,ip2...>
        if args.ip:
            # OR between submitted ips/ranges
            filter_.add_condition(Condition(args.ip.split(','), FilterData.IP))

        # --hostname <hostname1,hostname2...>
        if args.hostname:
            # OR between submitted hostnames
            filter_.add_condition(Condition(args.hostname.split(','), FilterData.HOST))

        # --service <service1,service2...>
        if args.service:
            # OR between ips
            services = args.service.split(',')
            for s in services:
                if not self.settings.services.is_service_supported(s, multi=False):
                    logger.error('Service {name} is not valid/supported'.format(
                        name=s.lower()))
                    print()
                    return
            filter_.add_condition(Condition(services, FilterData.SERVICE_EXACT))

        # --port <port1,port2...>
        if args.port:
            # OR between ports/port-ranges
            filter_.add_condition(Condition(args.port.split(','), FilterData.PORT))

        # --proto <protocol>
        if args.proto:
            filter_.add_condition(Condition(args.proto, FilterData.PROTOCOL))

        # --search <string>
        if args.search:
            filter_search = Filter(FilterOperator.OR)
            filter_search.add_condition(Condition(args.search, FilterData.OPTION_NAME))
            filter_search.add_condition(Condition(args.search, FilterData.OPTION_VALUE))
            filter_.add_condition(filter_search)

        # <option_name1> <option_name2> ...
        if args.names:
            for n in args.names:
                if not self.settings.services.is_specific_option_name_supported(n):
                    logger.error('Option "{name}" is not valid/supported'.format(
                        name=n.lower()))
                    print()
                    return
            filter_.add_condition(Condition(args.names, FilterData.OPTION_NAME))

        # --order <column>
        if args.order:
            req.order_by(args.order)

        try:
            req.add_filter(filter_)
        except FilterException as e:
            logger.error(e)
            print()
            return

        # Operations:
        # -----------
        # --del
        if args.delete:
            if not req.filter_applied:
                if not self.__confirm_for_all('delete ALL options'):
                    return
            req.delete()

        # Display (default)
        else:
            req.show() 

        print()


    #------------------------------------------------------------------------------------
    # Products Management

    products = argparse.ArgumentParser(
        description='Products in the current mission scope', 
        formatter_class=formatter_class)

    products_filters = products.add_argument_group('Filter products')
    products_filters.add_argument(
        '-I', '--ip', 
        action  = 'store', 
        metavar = '<ip1,ip2...>', 
        help    = 'Search for a list of IPs (single IP/CIDR range comma-separated)')
    products_filters.add_argument(
        '-H', '--hostname', 
        action  = 'store', 
        metavar = '<hostname1,hostname2...>', 
        help    = 'Search for a list of hostnames (comma-separated)')
    products_filters.add_argument(
        '-s', '--service', 
        action  = 'store', 
        metavar = '<service1,service2...>', 
        help    = 'Services to select')
    products_filters.add_argument(
        '-p', '--port', 
        action  = 'store', 
        metavar = '<port1,port2...>', 
        help    = 'Search for a list of ports (single/range comma-separated)')   
    products_filters.add_argument(
        '-r', '--proto', 
        action  = 'store', 
        metavar = '<protocol>', 
        help    = 'Only show [tcp|udp] services')
    products_filters.add_argument(
        '-S', '--search', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Search string to filter by')
    products_filters.add_argument(
        '-o', '--order', 
        action  = 'store', 
        metavar = '<column>', 
        help    = 'Order rows by specified column')
    products_filters.add_argument(
        'types', 
        nargs   = '*', 
        metavar = '<product_type1> <product_type2> ...', 
        help    = 'Product types to select')

    products_manage = products.add_argument_group('Manage products')
    products_manage.add_argument(
        '-d', '--del', 
        action  = 'store_true', 
        dest    = 'delete', 
        help    = 'Delete selected product(s) (instead of displaying)')


    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(products)
    def do_products(self, args):
        """Products in the current mission scope"""

        print()
        req = ProductsRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Filtering options:
        # ------------------
        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)

        # --ip <ip1,ip2...>
        if args.ip:
            # OR between submitted ips/ranges
            filter_.add_condition(Condition(args.ip.split(','), FilterData.IP))

        # --hostname <hostname1,hostname2...>
        if args.hostname:
            # OR between submitted hostnames
            filter_.add_condition(Condition(args.hostname.split(','), FilterData.HOST))

        # --service <service1,service2...>
        if args.service:
            # OR between ips
            services = args.service.split(',')
            for s in services:
                if not self.settings.services.is_service_supported(s, multi=False):
                    logger.error('Service {name} is not valid/supported'.format(
                        name=s.lower()))
                    print()
                    return
            filter_.add_condition(Condition(services, FilterData.SERVICE_EXACT))

        # --port <port1,port2...>
        if args.port:
            # OR between ports/port-ranges
            filter_.add_condition(Condition(args.port.split(','), FilterData.PORT))

        # --proto <protocol>
        if args.proto:
            filter_.add_condition(Condition(args.proto, FilterData.PROTOCOL))

        # --search <string>
        if args.search:
            filter_search = Filter(FilterOperator.OR)
            filter_search.add_condition(Condition(args.search, FilterData.PRODUCT_TYPE))
            filter_search.add_condition(Condition(args.search, FilterData.PRODUCT_NAME))
            filter_search.add_condition(Condition(args.search, 
                FilterData.PRODUCT_VERSION))
            filter_.add_condition(filter_search)

        # <product_type1> <product_type2> ...
        if args.types:
            for t in args.types:
                if not self.settings.services.is_product_type_supported(t):
                    logger.error('Product type "{type}" is not valid/supported'.format(
                        type=t.lower()))
                    print()
                    return
            filter_.add_condition(Condition(args.types, FilterData.PRODUCT_TYPE))

        # --order <column>
        if args.order:
            req.order_by(args.order)

        try:
            req.add_filter(filter_)
        except FilterException as e:
            logger.error(e)
            print()
            return

        # Operations:
        # -----------
        # --del
        if args.delete:
            if not req.filter_applied:
                if not self.__confirm_for_all('delete ALL products'):
                    return
            req.delete()

        # Display (default)
        else:
            req.show() 

        print()


    #------------------------------------------------------------------------------------
    # Import Nmap

    nmap = argparse.ArgumentParser(
        description='Import Nmap results (XML)', 
        formatter_class=formatter_class, 
        epilog='Note: it is recommended to run Nmap scans with -A or -sV options ' \
            'in order to get service\nbanners in imported results. If you import ' \
            'results from a scan run without version detection,\nyou can add ' \
            '--version-detection to tell Jok3r to run Nmap version detection for ' \
            'each service\nit has not been already run.')
    nmap.add_argument(
        '-n', '--no-http-recheck', 
        action  = 'store_true', 
        help    = 'Do not recheck for HTTP services')
    nmap.add_argument(
        '--no-html-title', 
        action  = 'store_true', 
        help    = 'Do not grab HTML title for HTTP services')
    nmap.add_argument(
        '--no-web-technos-detection',
        action  = 'store_true',
        help    = 'Disable web technologies detection for HTTP services')
    nmap.add_argument(
        '--version-detection',
        action  = 'store_true',
        help    = 'Run Nmap version detection for each service with no banner')
    nmap.add_argument(
        'file', 
        nargs   = 1, 
        metavar = '<xml-results>', 
        help    = 'Nmap XML results file')

    @cmd2.with_category(CMD_CAT_IMPORT)
    @cmd2.with_argparser(nmap)
    def do_nmap(self, args):
        """Import Nmap results"""
        print()

        # Check files
        files = glob(os.path.expanduser(args.file[0]))
        for file in files:
            if not FileUtils.can_read(file):
                logger.error('Cannot read specified file')
                print()
                return
            
            logger.info('Importing Nmap results from {file}'.format(file=file))
            if not args.no_http_recheck:
                logger.info('Each service will be re-checked to detect HTTP services. ' \
                    'Use --no-http-recheck if you want to disable it (faster import)')

            # Parse Nmap file
            parser = NmapResultsParser(file, self.settings.services)
            results = parser.parse(
                http_recheck=not args.no_http_recheck,
                html_title_grabbing=not args.no_html_title,
                nmap_banner_grabbing=args.version_detection,
                web_technos_detection=not args.no_web_technos_detection)
            print()

            if results is not None:
                if len(results) == 0:
                    logger.warning('No new service has been added into current mission')
                else:
                    logger.info('Update the database...')
                    req = HostsRequester(self.sqlsess)
                    req.select_mission(self.current_mission)
                    for host in results:
                        req.add_or_merge_host(host)
                    logger.success('Nmap results imported with success into current mission')

            print()


    def complete_nmap(self, text, line, begidx, endidx):
        """Complete with filename"""
        flag_dict = {
            'nmap': self.path_complete,
            '-n'  : self.path_complete, 
        }

        return self.flag_based_complete(text, line, begidx, endidx, flag_dict=flag_dict)

    #------------------------------------------------------------------------------------
    # Import Shodan host

    shodan = argparse.ArgumentParser(
        description='Import Shodan host (ips)', 
        formatter_class=formatter_class)
    shodan.add_argument(
        '-n', '--no-http-recheck', 
        action  = 'store_true', 
        help    = 'Do not recheck for HTTP services')
    shodan.add_argument(
        'ips', 
        nargs   = 1, 
        metavar = '<ip1,ip2...>', 
        help    = 'Import a list of IPs (single IP comma-separated)')

    @cmd2.with_category(CMD_CAT_IMPORT)
    @cmd2.with_argparser(shodan)
    def do_shodan(self, args):
        """Import Shodan results"""
        print()

        # Before all, check if we have a defined Shodan API key
        if 'shodan' not in API_KEYS.keys() or not API_KEYS['shodan']:
            logger.error('You must add a valid Shodan API key in "apikeys.py" to use '\
                'this feature')
            print()
            return

        # Check IPs
        ips = args.ips[0]
        if not ips:
            logger.error('Please type an ip address or several seperated with comma')
            print()
            return
        ips = ips.split(',')

        valid_ips = list()
        for ip in ips:
            if not NetUtils.is_valid_ip(ip):
                logger.warning(
                    '{ip} is an invalid IP address, it will be skipped'.format(ip=ip))
            else:
                valid_ips.append(ip)

        if len(valid_ips) == 0:
            logger.error('No valid IP address has been provided')
            print()
            return

        # Request Shodan API and parse results
        parser = ShodanResultsParser(valid_ips, self.settings.services)
        if parser is None:
            print()
            return
        results = parser.parse(http_recheck=not args.no_http_recheck)
        print()

        if results is not None:
            if len(results) == 0:
                logger.warning('No new service has been added into current mission')
            else:
                req = HostsRequester(self.sqlsess)
                req.select_mission(self.current_mission)
                for host in results:
                    req.add_or_merge_host(host)
                logger.success('Shodan results imported with success into current mission')

        print()


    #------------------------------------------------------------------------------------
    # Import File

    file = argparse.ArgumentParser(
        description='Import a list of targets from a file\n' \
            'One target per line, with the following syntax:\n' \
            '- For any service: <IP/HOST>:<PORT>,<SERVICE>\n' \
            '- For HTTP service: <URL> (must begin with http(s)://)', 
        formatter_class=formatter_class)
    # file.add_argument(
    #     '--no-html-title', 
    #     action = 'store_true', 
    #     help   = 'Do not grab HTML title for HTTP services')
    file.add_argument(
        '--no-dns-reverse',
        action = 'store_true',
        help   = 'Do not perform reverse DNS lookup on IP addresses')
    file.add_argument(
        '--no-nmap-banner',
        action = 'store_true',
        help   = 'Disable Nmap banner grabbing')
    file.add_argument(
        'file', 
        nargs   = 1, 
        metavar = '<filename>', 
        help    = 'List of targets from a file')

    @cmd2.with_category(CMD_CAT_IMPORT)
    @cmd2.with_argparser(file)
    def do_file(self, args):
        """Import a list of targets from a file into current mission scope"""
        print()
        req = ServicesRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Check file
        file = os.path.expanduser(args.file[0])
        if not FileUtils.can_read(file):
            logger.error('Cannot read specified file')
            return

        logger.info('Importing targets from the file "{file}"'.format(file=file))

        # Parse file
        f = open(file, 'r').read().splitlines()

        if len(f) == 0:
            logger.warning('File is empty')
            return

        # Process all lines
        i = 1
        for l in f:
            if i > 1:
                print()
            logger.info('Processing line [{i}/{total}]: "{line}" ...'.format(
                i=i, total=len(f), line=l))
            i += 1

            # For line with syntax: <IP/HOST>:<PORT>,<SERVICE>
            if ',' in l:
                ip_port, service = l.split(',', maxsplit=1)
                if not self.settings.services.is_service_supported(service, multi=False):
                    logger.error('Service {name} is not valid/supported. ' \
                        'Line skipped'.format(name=service.lower()))
                    continue

                ip, port = ip_port.split(':', maxsplit=1)
                if not NetUtils.is_valid_port(port):
                    logger.error('Port is invalid, not in range [0-65535]. ' \
                        'Line skipped')
                    continue

                # Add the service in current mission scope
                up = req.add_service(
                    ip, 
                    port, 
                    self.settings.services.get_protocol(service),
                    service, 
                    self.settings.services,
                    nmap_banner_grabbing=not args.no_nmap_banner,
                    reverse_dns_lookup=not args.no_dns_reverse, 
                    availability_check=True,
                    html_title_grabbing=True,
                    web_technos_detection=True)

            # For line with syntax: <URL>
            elif l.lower().startswith('http://') or l.lower().startswith('https://'):

                if not WebUtils.is_valid_url(l):
                    logger.error('URL is invalid')
                else:
                    # Add the URL in current mission scope
                    req.add_url(l,
                                self.settings.services,
                                reverse_dns_lookup=not args.no_dns_reverse,
                                availability_check=True,
                                nmap_banner_grabbing=not args.no_nmap_banner,
                                html_title_grabbing=True,
                                web_technos_detection=True)

            else:
                logger.error('Incorrect syntax, line skipped')

        print()


    def complete_file(self, text, line, begidx, endidx):
        """Complete with filename"""
        flag_dict = {
            'file': self.path_complete,
            #'--no-html-title'  : self.path_complete,
            '--no-dns-reverse' : self.path_complete,
            '--no-nmap-banner' : self.path_complete,

        }

        return self.flag_based_complete(text, line, begidx, endidx, flag_dict=flag_dict)


    #------------------------------------------------------------------------------------
    # Vulns Display

    vulns = argparse.ArgumentParser(
        description='Vulnerabilities in the current mission scope', 
        formatter_class=formatter_class)

    vulns_filters = vulns.add_argument_group('Filter vulnerabilities')
    # vulns_filters.add_argument(
    #     '-H', '--hostname', 
    #     action  = 'store', 
    #     metavar = '<hostname1,hostname2...>', 
    #     help    = 'Search for a list of hostnames (comma-separated)')
    vulns_filters.add_argument(
        '-I', '--ip', 
        action  = 'store', 
        metavar = '<ip1,ip2...>', 
        help    = 'Search for a list of IPs (single IP/CIDR range comma-separated)')
    vulns_filters.add_argument(
        '-s', '--service', 
        action  = 'store', 
        metavar = '<service1,service2...>', 
        help    = 'Services to select')
    vulns_filters.add_argument(
        '-p', '--port', 
        action  = 'store', 
        metavar = '<port1,port2...>', 
        help    = 'Search for a list of ports (single/range comma-separated)')   
    vulns_filters.add_argument(
        '-r', '--proto', 
        action  = 'store', 
        metavar = '<protocol>', 
        help    = 'Only show [tcp|udp] services')
    vulns_filters.add_argument(
        '-S', '--search', 
        action  = 'store', 
        metavar = '<string>', 
        help    = 'Search string to filter by')
    vulns_filters.add_argument(
        '-o', '--order', 
        action  = 'store', 
        metavar = '<column>', 
        help    = 'Order rows by specified column')

    vulns_manage = vulns.add_argument_group('Manage vulnerabilities')
    vulns_manage.add_argument(
        '-d', '--del', 
        action  = 'store_true', 
        dest    = 'delete', 
        help    = 'Delete selected vulnerability(ies) (instead of displaying)')


    vulns_manage = vulns.add_argument_group('Display option')
    vulns_manage.add_argument(
        '--no-truncation', 
        action  = 'store_true', 
        dest    = 'no_truncation', 
        help    = 'Do not truncate vulnerability names (require sufficient terminal width)')

    @cmd2.with_category(CMD_CAT_RESULTS)
    @cmd2.with_argparser(vulns)
    def do_vulns(self, args):
        """Vulnerabilities in the current mission scope"""

        print()
        req = VulnsRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Filtering options:
        # ------------------
        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)

        # --ip <ip1,ip2...>
        if args.ip:
            # OR between submitted ips/ranges
            filter_.add_condition(Condition(args.ip.split(','), FilterData.IP))

        # --service <service1,service2...>
        if args.service:
            # OR between ips
            services = args.service.split(',')
            for s in services:
                if not self.settings.services.is_service_supported(s, multi=False):
                    logger.error('Service {name} is not valid/supported'.format(
                        name=s.lower()))
                    print()
                    return
            filter_.add_condition(Condition(services, FilterData.SERVICE_EXACT))

        # --port <port1,port2...>
        if args.port:
            # OR between ports/port-ranges
            filter_.add_condition(Condition(args.port.split(','), FilterData.PORT))

        # --proto <protocol>
        if args.proto:
            filter_.add_condition(Condition(args.proto, FilterData.PROTOCOL))

        # --search <string>
        if args.search:
            filter_search = Filter(FilterOperator.OR)
            filter_search.add_condition(Condition(args.search, FilterData.VULN))
            filter_.add_condition(filter_search)

        # --order <column>
        if args.order:
            req.order_by(args.order)

        try:
            req.add_filter(filter_)
        except FilterException as e:
            logger.error(e)
            print()
            return

        # Operations:
        # -----------
        # --del
        if args.delete:
            if not req.filter_applied:
                if not self.__confirm_for_all('delete ALL vulnerabilities'):
                    return

            req.delete()

        # Display (default)
        else:
            req.show(truncation=not args.no_truncation)

        print()


    #------------------------------------------------------------------------------------
    # Results

    results = argparse.ArgumentParser(
        description='Attacks results', 
        formatter_class=formatter_class)

    checks_filter = results.add_argument_group('Filters on checks')
    checks_filter.add_argument(
        '-s', '--service-id', 
        action  = 'store',
        metavar = '<service-id>', 
        help    = 'Service id to show results of')
    checks_filter.add_argument(
        '-n', '--check-name',
        action  = 'store',
        metavar = '<name>',
        help    = 'Search for check name')

    outputs_filter = results.add_argument_group('Filters on command outputs')
    outputs_filter_mxg = outputs_filter.add_mutually_exclusive_group()
    outputs_filter_mxg.add_argument(
        '-c', '--check-id', 
        action  = 'store', 
        metavar = '<check-id>', 
        help    = 'Show results (command outputs) for specified check')
    outputs_filter_mxg.add_argument(
        '-S', '--search',
        action  = 'store',
        metavar = '<string>',
        help    = 'Search for a string in results (command outputs). ' \
            'Accept wildcard: %%')
    outputs_filter.add_argument(
        '--nb-words',
        action  = 'store',
        metavar = '<nb>',
        default  = 12,
        help     = 'Number of words to show before and after match when using ' \
            '-S--search/--search (default: 12)')


    @cmd2.with_category(CMD_CAT_RESULTS)
    @cmd2.with_argparser(results)
    def do_results(self, args):
        """Attacks results"""
        print()

        # Required checks on arguments
        if (args.service_id or args.check_name) and (args.check_id or args.search):
            logger.error('--service-id|--check-name and --check-id|--search are '\
                'mutually exclusive')
            print()
            return

        if not args.service_id and not args.check_name and not args.check_id \
                and not args.search:
            logger.error('At least one argument required')
            print()
            return

        results_req = ResultsRequester(self.sqlsess)
        results_req.select_mission(self.current_mission)

        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)
        

        if args.service_id or args.check_name:            

            # --service-id <service-id>
            if args.service_id:
                try:
                    service_id = int(args.service_id)
                except:
                    logger.error('Invalid service id (wrong format)')
                    print()
                    return

                # Check service id exists
                # filter_svc = Filter()
                # filter_svc.add_condition(Condition(service_id, FilterData.SERVICE_ID))
                # services_req = ServicesRequester(self.sqlsess)
                # services_req.select_mission(self.current_mission)
                # services_req.add_filter(filter_svc)
                # if not services_req.get_first_result():
                #     logger.error('Invalid service id (not existing)')
                #     return

                filter_.add_condition(Condition(service_id, FilterData.SERVICE_ID))

            # --check-name <name>
            if args.check_name:
                filter_.add_condition(Condition(args.check_name, FilterData.CHECK_NAME))

            results_req.add_filter(filter_)
            results_req.show()            

        else:

            # --check-id <check-id>
            if args.check_id:
                try:
                    check_id = int(args.check_id)
                except:
                    logger.error('Invalid check id (wrong format)')
                    print()
                    return

                filter_.add_condition(Condition(args.check_id, FilterData.CHECK_ID))
                results_req.add_filter(filter_)
                results_req.show_command_outputs_for_check()

            # --search <string>
            elif args.search:
                outputs_req = CommandOutputsRequester(self.sqlsess)
                outputs_req.select_mission(self.current_mission)

                filter_.add_condition(Condition(args.search, FilterData.COMMAND_OUTPUT))
                outputs_req.add_filter(filter_)
                outputs_req.show_search_results(args.search, args.nb_words)

        print()             


    #------------------------------------------------------------------------------------
    # Report

    report = argparse.ArgumentParser(
        description='Generate an HTML Report with all data and checks outputs from \n' \
            'the current mission',
        formatter_class=formatter_class)
    report.add_argument(
        '--no-screen',
        action = 'store_true',
        help   = 'Disable not take web page screenshots')
    report.add_argument(
        'path', 
        nargs   = '?', 
        metavar = '<path>', 
        default = REPORT_PATH,
        help    = 'Output path (default: reports/)')

    @cmd2.with_category(CMD_CAT_REPORTING)
    @cmd2.with_argparser(report)
    def do_report(self, args):
        """HTML Reporting"""
        print()

        # Check output path
        if not FileUtils.exists(args.path):
            logger.error('Output path does not exist !')
            print()
            return

        reporter = Reporter(self.current_mission, 
                            self.sqlsess,
                            self.settings,
                            args.path, 
                            do_screens=not args.no_screen)
        reporter.run()

        print()


    #------------------------------------------------------------------------------------

    def __confirm_for_all(self, action):
        """
        Print a prompt to confirm an action

        :param str action: Action to perform
        :return: Answer from the user
        :rtype: bool
        """
        if not Output.prompt_confirm('No filter applied. Are you sure you ' \
                'want to {action} in current mission ?'.format(action=action), 
                default=False):
            logger.info('Canceled')
            print()
            return False
        else:
            return True