# -*- coding: utf-8 -*-
###
### Core > Db Controller
###
import os
import sys
import cmd2
import argparse

from lib.controller.Controller import Controller
from lib.core.Config import *
from lib.core.Constants import *
from lib.core.Exceptions import FilterException
from lib.core.NmapResultsParser import NmapResultsParser
from lib.core.Target import Target
from lib.utils.ArgParseUtils import *
from lib.utils.FileUtils import FileUtils
from lib.utils.NetUtils import NetUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Mission import Mission
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.CredentialsRequester import CredentialsRequester
from lib.requester.HostsRequester import HostsRequester
from lib.requester.MissionsRequester import MissionsRequester
from lib.requester.ResultsRequester import ResultsRequester
from lib.requester.ServicesRequester import ServicesRequester
from lib.output.Logger import logger
from lib.output.Output import Output


class DbController(cmd2.Cmd):

    # Command categories
    CMD_CAT_MISSION_SCOPE = 'Missions data'
    CMD_CAT_IMPORT        = 'Import'
    CMD_CAT_RESULTS       = 'Attacks results'

    intro = DB_INTRO
    formatter_class = lambda prog: LineWrapRawTextHelpFormatter(prog, max_help_position=ARGPARSE_MAX_HELP_POS)

    def __init__(self, arguments, settings, sqlsession):
        self.arguments = arguments
        self.settings  = settings
        self.sqlsess   = sqlsession

        super().__init__(use_ipython=False, 
                         persistent_history_file=DB_HIST_FILE, 
                         persistent_history_length=500)

        #self.cmdqueue.append('alias help "help -v"')
        self.allow_cli_args = False

        # Delete useless cmd2 built-in commands
        del cmd2.Cmd.do_edit
        del cmd2.Cmd.do_load
        del cmd2.Cmd.do_py
        del cmd2.Cmd.do_pyscript
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
            self.prompt = Output.colored('jok3rdb', color='light_green', attrs='bold') + \
                          Output.colored('[{mission}]'.format(mission=name), color='light_blue', attrs='bold') + \
                          Output.colored('> ', color='light_green', attrs='bold')
            if verbose: logger.info('Selected mission is now {name}'.format(name=name))


    @cmd2.with_argument_list
    def do_help(self, args):
        """Display this help message"""
        super().do_help('-v' if not args else args)


    # --- Mission
    mission = argparse.ArgumentParser(description='Manage missions', formatter_class=formatter_class)
    mission_mxg = mission.add_mutually_exclusive_group()
    mission_mxg.add_argument('-a', '--add', action='store', metavar='<name>', help='Add mission')
    mission_mxg.add_argument('-c', '--comment', nargs=2, metavar=('<name>','<comment>'), help='Change the comment of a mission')
    mission_mxg.add_argument('-d', '--del', action='store', dest='delete', metavar='<name>', help='Delete mission')
    mission_mxg.add_argument('-D', '--reset', action='store_true', help='Delete all missions')
    mission_mxg.add_argument('-r', '--rename', nargs=2, metavar=('<old>','<new>'), help='Rename mission')
    mission_mxg.add_argument('-S', '--search', action='store', metavar='<string>', help='Search string to filter by')
    mission_mxg.add_argument('name', nargs='?', metavar='<name>', help='Switch mission')

    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(mission)
    def do_mission(self, args):
        """Missions management"""
        print()

        req = MissionsRequester(self.sqlsess)
        if args.add:
            if req.add(args.add):
                self.change_current_mission(args.add, verbose=True)
        elif args.comment:
            req.add_filter(Condition(args.comment[0], FilterData.MISSION_EXACT))
            req.edit_comment(args.comment[1])
        elif args.delete:
            req.add_filter(Condition(args.delete, FilterData.MISSION_EXACT))
            req.delete()        
        elif args.reset:
            if Output.prompt_confirm('Are you sure you want to delete all missions ?', default=False):
                req.reset()
        elif args.rename:
            req.rename(args.rename[0], args.rename[1])
        elif args.search:
            filter_ = Filter()
            filter_.add_condition(Condition(args.search, FilterData.MISSION))
            filter_.add_condition(Condition(args.search, FilterData.COMMENT_MISSION))
            req.add_filter(filter_)
            req.show(self.current_mission)
        elif args.name:
            self.change_current_mission(args.name, verbose=True)
        else:
            print('All available missions:')
            req.show(self.current_mission)

        print()

    def complete_mission(self, text, line, begidx, endidx):
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


    # --- Hosts
    hosts = argparse.ArgumentParser(description='Hosts in the current mission scope', formatter_class=formatter_class)
    hosts_manage = hosts.add_argument_group('Manage hosts').add_mutually_exclusive_group()
    hosts_manage.add_argument('-c', '--comment', action='store', metavar='<comment>', help='Change the comment of selected host(s)')
    hosts_manage.add_argument('-d', '--del', action='store_true', dest='delete', help='Delete selected host(s) (instead of displaying)')
    hosts_filters = hosts.add_argument_group('Filter hosts')
    hosts_filters.add_argument('-o', '--order', action='store', metavar='<column>', help='Order rows by specified column')
    hosts_filters.add_argument('-S', '--search', action='store', metavar='<string>', help='Search string to filter by')
    hosts_filters.add_argument('addrs', nargs='*', metavar='<addr1> <addr2> ...', help='IPs/CIDR ranges/hostnames to select')

    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(hosts)
    def do_hosts(self, args):
        """Hosts in the current mission scope"""
        print()
        req = HostsRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)
        if args.addrs:
            for addr in args.addrs:
                if NetUtils.is_valid_ip(addr) or NetUtils.is_valid_ip_range(addr):
                    filter_.add_condition(Condition(addr, FilterData.IP))
                else:
                    filter_.add_condition(Condition(addr, FilterData.HOST))
        if args.search:
            filter_search = Filter(FilterOperator.OR)
            filter_search.add_condition(Condition(args.search, FilterData.HOST))
            filter_search.add_condition(Condition(args.search, FilterData.OS))
            filter_search.add_condition(Condition(args.search, FilterData.COMMENT_HOST))
            filter_.add_condition(filter_search)
        if args.order:
            req.order_by(args.order)

        try:
            req.add_filter(filter_)
        except FilterException as e:
            logger.error(e)
            return

        # Operations
        if args.comment:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to edit comment for ALL hosts in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.edit_comment(args.comment)
        elif args.delete:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to delete ALL hosts and related services in current mission', default=False):
                    logger.info('Canceled')
                    return
            req.delete()
        else:
            req.show()

        print()


    # --- Services
    services = argparse.ArgumentParser(description='Services in the current mission scope', formatter_class=formatter_class)
    services_manage = services.add_argument_group('Manage services').add_mutually_exclusive_group()
    services_manage.add_argument('-a', '--add', action='store', nargs=3, metavar=('<host>','<port>','<service>'), help='Add a new service')
    services_manage.add_argument('-u', '--url', action='store', metavar='<url>', help='Add a new URL')
    services_manage.add_argument('-d', '--del', action='store_true', dest='delete', help='Delete selected service(s) (instead of displaying)')
    services_manage.add_argument('-c', '--comment', action='store', metavar='<comment>', help='Change the comment of selected service(s)')
    services_manage.add_argument('--https', action='store_true', help='Switch between HTTPS and HTTP protocol for URL of selected service(s)')
    services_creds = services.add_argument_group('Manage services credentials').add_mutually_exclusive_group()
    services_creds.add_argument('--addcred', action='store', nargs=2, metavar=('<user>','<pass>'), 
                              help='Add new credentials (username+password) for selected service(s)')
    services_creds.add_argument('--addcred-http', action='store', nargs=3, metavar=('<user>','<pass>','<auth-type>'), 
                              help='Add new credentials (username+password) for the specified authentication type on selected HTTP service(s)')
    services_creds.add_argument('--adduser', action='store', nargs=1, metavar=('<user>'), 
                              help='Add new username (password unknown) for selected service(s)')
    services_creds.add_argument('--adduser-http', action='store', nargs=2, metavar=('<user>','<auth-type>'), 
                              help='Add new username (password unknown) for the specified authentication type on selected HTTP service(s)')
    services_filters = services.add_argument_group('Filter services')
    services_filters.add_argument('-H', '--hostname', action='store', metavar='<hostname1,hostname2...>', help='Search for a list of hostnames (comma-separated)')
    services_filters.add_argument('-I', '--ip', action='store', metavar='<ip1,ip2...>', help='Search for a list of IPs (single IP/CIDR range comma-separated)')
    services_filters.add_argument('-p', '--port', action='store', metavar='<port1,port2...>', help='Search for a list of ports (single/range comma-separated)')   
    services_filters.add_argument('-r', '--proto', action='store', metavar='<protocol>', help='Only show [tcp|udp] services')
    services_filters.add_argument('-U', '--up', action='store_true', help='Only show services which are up')
    services_filters.add_argument('-o', '--order', action='store', metavar='<column>', help='Order rows by specified column')
    services_filters.add_argument('-S', '--search', action='store', metavar='<string>', help='Search string to filter by')
    services_filters.add_argument('names', nargs='*', metavar='<name1> <name2> ...', help='Services to select')

    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(services)
    def do_services(self, args):
        """Services in the current mission scope"""
        print()
        req = ServicesRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)
        if args.names:
            for n in args.names:
                if not self.settings.services.is_service_supported(n, multi=False):
                    logger.error('Service {name} is not valid/supported'.format(name=n.lower()))
                    return
            filter_.add_condition(Condition(args.names, FilterData.SERVICE_EXACT))

        if args.order:
            req.order_by(args.order)

        if args.hostname:
            # OR between submitted hostnames
            filter_.add_condition(Condition(args.hostname.split(','), FilterData.HOST))
        if args.ip:
            # OR between submitted ips/ranges
            filter_.add_condition(Condition(args.ip.split(','), FilterData.IP))
        if args.port:
            # OR between ports/port-ranges
            filter_.add_condition(Condition(args.port.split(','), FilterData.PORT))
        if args.proto:
            filter_.add_condition(Condition(args.proto, FilterData.PROTOCOL))
        if args.up:
            filter_.add_condition(Condition(args.up, FilterData.UP))
        if args.search:
            filter_search = Filter(FilterOperator.OR)
            filter_search.add_condition(Condition(args.search, FilterData.HOST))
            filter_search.add_condition(Condition(args.search, FilterData.BANNER))
            filter_search.add_condition(Condition(args.search, FilterData.URL))
            filter_search.add_condition(Condition(args.search, FilterData.COMMENT_SERVICE))
            filter_.add_condition(filter_search)

        try:
            req.add_filter(filter_)
        except FilterException as e:
            logger.error(e)
            return

        # Operations
        if args.add:
            host, port, service = args.add
            if NetUtils.is_valid_ip(host):
                ip = host
                hostname = NetUtils.reverse_dns_lookup(ip) 
                logger.info('Reverse DNS lookup on IP {ip}: {hostname}'.format(ip=ip, hostname=hostname))
            else:
                ip = NetUtils.dns_lookup(host)
                if not ip:
                    logger.error('Cannot resolve hostname')
                    return
                hostname = host
                logger.info('DNS lookup on {hostname}: IP {ip}'.format(hostname=host, ip=ip))

            if not NetUtils.is_valid_port(port):
                logger.error('Port is invalid, not in range [0-65535]')
            elif not self.settings.services.is_service_supported(service, multi=False):
                logger.error('Service {name} is not valid/supported'.format(name=service.lower()))
            else:
                req.add_service(ip, hostname, port, self.settings.services.get_protocol(service), service)
        elif args.url:
            args.url = WebUtils.add_prefix_http(args.url)
            if not WebUtils.is_valid_url(args.url):
                logger.error('URL is invalid')
            else:
                req.add_url(args.url)
        elif args.delete:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to delete ALL services in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.delete()
        elif args.comment:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to edit comment for ALL services in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.edit_comment(args.comment)
        elif args.https:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to apply switch for ALL URLs in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.switch_https()         
        elif args.addcred:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to add same creds for ALL services in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.add_cred(args.addcred[0], args.addcred[1], None) 
        elif args.addcred_http:
            if not req.are_only_http_services_selected():
                logger.warning('Some non-HTTP services are selected. Use --addcred instead for non-HTTP services')
                return
            if not self.settings.services.is_valid_authentication_type(args.addcred_http[2]):
                logger.warning('Invalid HTTP authentication type')
                logger.info('List of supported authentication types: ')
                for auth_type in self.settings.services.get_authentication_types('http'):
                    logger.info('- {type}'.format(type=auth_type))
                return
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to add same creds for ALL HTTP services in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.add_cred(args.addcred_http[0], args.addcred_http[1], args.addcred_http[2]) 
        elif args.adduser:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to add same username for ALL services in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.add_cred(args.adduser[0], None, None)
        elif args.adduser_http:
            if not req.are_only_http_services_selected():
                logger.warning('Some non-HTTP services are selected. Use --adduser instead for non-HTTP services')
                return
            if not self.settings.services.is_valid_authentication_type(args.adduser_http[1]):
                logger.warning('Invalid HTTP authentication type')
                logger.info('List of supported authentication types: ')
                for auth_type in self.settings.services.get_authentication_types('http'):
                    logger.info('- {type}'.format(type=auth_type))
                return
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to add same username for ALL HTTP services in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.add_cred(args.adduser_http[0], None, args.adduser_http[1]) 
        else:
            req.show()                      

        print()


    # --- Creds
    creds = argparse.ArgumentParser(description='Credentials in the current mission scope', formatter_class=formatter_class,
        epilog='Note: you can also use "services --addcred/--addonlyuser" to add new creds')
    creds_manage = creds.add_argument_group('Manage credentials').add_mutually_exclusive_group()
    creds_manage.add_argument('--addcred', action='store', nargs=3, metavar=('<service-id>','<user>','<pass>'), 
                              help='Add new credentials (username+password) for the given service')
    creds_manage.add_argument('--addcred-http', action='store', nargs=4, metavar=('<service-id>','<user>','<pass>','<auth-type>'), 
                              help='Add new credentials (username+password) for the specified authentication type on HTTP service')
    creds_manage.add_argument('--adduser', action='store', nargs=2, metavar=('<service-id>','<user>'), 
                              help='Add new username (password unknown) for the given service')
    creds_manage.add_argument('--adduser-http', action='store', nargs=3, metavar=('<service-id>','<user>','<auth-type>'), 
                              help='Add new username (password unknown) for the specified authentication type on HTTP service')
    creds_manage.add_argument('-c', '--comment', action='store', metavar='<comment>', help='Change the comment of selected cred(s)')
    creds_manage.add_argument('-d', '--del', action='store_true', dest='delete', help='Delete selected credential(s) (instead of displaying)')
    creds_filters = creds.add_argument_group('Filter credentials')
    creds_filters.add_argument('-U', '--username', action='store', metavar='<string>', help='Select creds with username matching this string')
    creds_filters.add_argument('-P', '--password', action='store', metavar='<string>', help='Select creds with password matching this string')
    creds_filters_mxg = creds_filters.add_mutually_exclusive_group()
    creds_filters_mxg.add_argument('-b', '--both', action='store_true', help='Select creds where username and password are both set (no single username)')
    creds_filters_mxg.add_argument('-u', '--onlyuser', action='store_true', help='Select creds where only username is set')
    creds_filters.add_argument('-H', '--hostname', action='store', metavar='<hostname1,hostname2...>', help='Select creds for a list of hostnames (comma-separated)')
    creds_filters.add_argument('-I', '--ip', action='store', metavar='<ip1,ip2...>', help='Select creds for a list of IPs (single IP/CIDR range comma-separated)')
    creds_filters.add_argument('-p', '--port', action='store', metavar='<port1,port2...>', help='Select creds a list of ports (single/range comma-separated)')   
    creds_filters.add_argument('-s', '--service', action='store', metavar='<svc1,svc2...>', help='Select creds for a list of services (comma-separated)')
    creds_filters.add_argument('-o', '--order', action='store', metavar='<column>', help='Order rows by specified column')
    creds_filters.add_argument('-S', '--search', action='store', metavar='<string>', help='Search string to filter by')


    @cmd2.with_category(CMD_CAT_MISSION_SCOPE)
    @cmd2.with_argparser(creds)
    def do_creds(self, args):
        """Credentials in the current mission scope"""
        print()
        req = CredentialsRequester(self.sqlsess)
        req.select_mission(self.current_mission)

        # Logical AND is applied between all specified filtering options
        filter_ = Filter(FilterOperator.AND)
        if args.username:
            filter_.add_condition(Condition(args.username, FilterData.USERNAME))
        if args.password:
            filter_.add_condition(Condition(args.password, FilterData.PASSWORD))
        if args.both:
            filter_.add_condition(Condition(args.both, FilterData.USER_AND_PASS))
        elif args.onlyuser:
            filter_.add_condition(Condition(args.onlyuser, FilterData.ONLY_USER))
        if args.hostname:
            # OR between submitted hostnames
            filter_.add_condition(Condition(args.hostname.split(','), FilterData.HOST))
        if args.ip:
            # OR between submitted ips/ranges
            filter_.add_condition(Condition(args.ip.split(','), FilterData.IP))
        if args.port:
            # OR between ports/port-ranges
            filter_.add_condition(Condition(args.port.split(','), FilterData.PORT))
        if args.service:
            for s in args.service.split(','):
                if not self.settings.services.is_service_supported(s, multi=False):
                    logger.error('Service {name} is not valid/supported'.format(name=s.lower()))
                    return
            filter_.add_condition(Condition(args.service.split(','), FilterData.SERVICE_EXACT))
        if args.order:
            req.order_by(args.order)
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
            return

        # Operations
        add = args.addcred or args.addcred_http or args.adduser or args.adduser_http
        if add:
            try:
                service_id = int(add[0])
            except:
                logger.error('Invalid service id')
                return

            if args.addcred:
                req.add_cred(service_id, args.add[1], args.add[2], None)
            elif args.addcred_http:
                if not self.settings.services.is_valid_authentication_type(args.addcred_http[3]):
                    logger.warning('Invalid HTTP authentication type')
                    logger.info('List of supported authentication types: ')
                    for auth_type in self.settings.services.get_authentication_types('http'):
                        logger.info('- {type}'.format(type=auth_type))
                    return
                req.add_cred(service_id, args.addcred_http[1], args.addcred_http[2], args.addcred_http[3])
            elif args.adduser:
                req.add_cred(service_id, args.add[1], None, None)
            elif args.adduser_http:
                if not self.settings.services.is_valid_authentication_type(args.adduser_http[2]):
                    logger.warning('Invalid HTTP authentication type')
                    logger.info('List of supported authentication types: ')
                    for auth_type in self.settings.services.get_authentication_types('http'):
                        logger.info('- {type}'.format(type=auth_type))
                    return
                req.add_cred(service_id, args.adduser_http[1], None, args.adduser_http[2])
        elif args.comment:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to edit comment for ALL creds in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.edit_comment(args.comment)
        elif args.delete:
            if not req.filter_applied:
                if not Output.prompt_confirm('No filter applied. Are you sure you want to delete ALL creds in current mission ?', default=False):
                    logger.info('Canceled')
                    return
            req.delete()
        else:
            if not args.order:
                req.order_by('ip')
            req.show()

        print()


    # --- Nmap
    nmap = argparse.ArgumentParser(description='Import Nmap results', formatter_class=formatter_class)
    nmap.add_argument('-n', '--no-http-recheck', action='store_true', help='Do not recheck for HTTP services')
    nmap.add_argument('file', nargs=1, metavar='<xml-results>', help='Nmap XML results file')

    @cmd2.with_category(CMD_CAT_IMPORT)
    @cmd2.with_argparser(nmap)
    def do_nmap(self, args):
        """Import Nmap results"""
        print()

        file = os.path.expanduser(args.file[0])
        if not FileUtils.can_read(file):
            logger.error('Cannot read specified file')
            return
        logger.info('Importing Nmap results from {file}'.format(file=file))
        if not args.no_http_recheck:
            logger.info('Each service will be re-checked to detect HTTP services. Use --no-http-recheck if you want to disable it (faster import)')

        parser = NmapResultsParser(file, self.settings.services)
        results = parser.parse(not args.no_http_recheck)
        if results is not None:
            if len(results) == 0:
                logger.warning('No new service has been added into current mission')
            else:
                req = HostsRequester(self.sqlsess)
                req.select_mission(self.current_mission)
                for host in results:
                    req.add_or_merge_host(host)
                logger.success('Nmap results imported with success into current mission')

        print()


    def complete_nmap(self, text, line, begidx, endidx):
        flag_dict = {
            'nmap': self.path_complete,
            '-n'  : self.path_complete, 
        }

        return self.flag_based_complete(text, line, begidx, endidx, flag_dict=flag_dict)


    # --- Results
    results = argparse.ArgumentParser(description='Attacks results', formatter_class=formatter_class)
    results.add_argument('-s', '--show', action='store', metavar='<check-id>', help='Show results for specified check')
    results.add_argument('service_id', nargs='?', metavar='<service-id>', help='Service id')

    @cmd2.with_category(CMD_CAT_RESULTS)
    @cmd2.with_argparser(results)
    def do_results(self, args):
        """Attacks results"""
        print()

        req = ResultsRequester(self.sqlsess)
        #req.select_mission(self.current_mission)

        if args.show:
            try:
                check_id = int(args.show)
            except:
                logger.error('Invalid check id')
                return
            req.show_command_outputs(check_id)
        elif args.service_id:
            try:
                service_id = int(args.service_id)
            except:
                logger.error('Invalid service id')
                return
            req.show_results(service_id)

        print()             

