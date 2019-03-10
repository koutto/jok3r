#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Arguments parser
###
# PYTHON_ARGCOMPLETE_OK
import sys

from lib.core.Config import *
from lib.core.Constants import *
from lib.core.Exceptions import ArgumentsException
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.utils.ArgParseUtils import *
from lib.utils.FileUtils import FileUtils
from lib.utils.WebUtils import WebUtils
from lib.output.Logger import logger
from lib.output.Output import Output


class ArgumentsParser:

    formatter_class = lambda prog: LineWrapRawTextHelpFormatter(
        prog, max_help_position=ARGPARSE_MAX_HELP_POS)


    def __init__(self, settings):
        self.settings = settings
        self.mode     = None
        self.args     = None

        parser = argparse.ArgumentParser(
            usage=USAGE, 
            formatter_class=ArgumentsParser.formatter_class)
        parser.add_argument('command', help=argparse.SUPPRESS)

        # https://chase-seibert.github.io/blog/2014/03/21/python-multilevel-argparse.html
        # parse_args defaults to [1:] for args, but need to exclude the rest of the args
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            logger.error('Unrecognized command')
            parser.print_help()
            raise ArgumentsException()

        self.subparser = None

        # Use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

        # Check arguments
        if not self.check_args():
            raise ArgumentsException()


    #------------------------------------------------------------------------------------

    def __create_subcmd_parser(self):
        """Create subcommand parser."""

        subcmd = {
            Mode.TOOLBOX : 'toolbox',
            Mode.INFO    : 'info',
            Mode.DB      : 'db',
            Mode.ATTACK  : 'attack'
        }.get(self.mode)

        return argparse.ArgumentParser(
            usage='python3 jok3r.py {subcmd} <args>'.format(subcmd=subcmd),
            formatter_class=ArgumentsParser.formatter_class) 


    #------------------------------------------------------------------------------------
    # Toolbox Subcommand Parsing
    
    def toolbox(self):
        """Arguments for subcommand Toolbox"""

        self.mode = Mode.TOOLBOX

        parser = self.__create_subcmd_parser()
        toolbox = parser.add_argument_group(
            Output.colored('Toolbox management', attrs='bold'), 
            'The Toolbox contains all the tools used by Jok3r for running the security' \
            'checks.\nThey are classified by the services they target.')

        toolbox_mxg = toolbox.add_mutually_exclusive_group()
        toolbox_mxg.add_argument(
            '--show', 
            help    = 'Show toolbox content for a given service', 
            action  = 'store', 
            dest    = 'show_toolbox_for_svc', 
            metavar = '<service>', 
            default = None)
        toolbox_mxg.add_argument(
            '--show-all', 
            help    = 'Show full toolbox content', 
            action  = 'store_true', 
            dest    = 'show_toolbox_all', 
            default = False)
        toolbox_mxg.add_argument(
            '--install', 
            help    = 'Install the tools targeting a given service', 
            action  = 'store', 
            dest    = 'install_for_svc', 
            metavar = '<service>', 
            default = None)
        toolbox_mxg.add_argument(
            '--install-all', 
            help    = 'Install all the tools in the toolbox',
            action  = 'store_true', 
            dest    = 'install_all', 
            default = False)
        toolbox_mxg.add_argument(
            '--update', 
            help    = 'Update the installed tools targeting a given service',
            action  = 'store', 
            dest    = 'update_for_svc', 
            metavar = '<service>', 
            default = None)
        toolbox_mxg.add_argument(
            '--update-all',
            help    = 'Update all installed tools in the toolbox',
            action  = 'store_true', 
            dest    = 'update_all', 
            default = False)
        toolbox_mxg.add_argument(
            '--uninstall', 
            help    = 'Uninstall the tools targeting a given service',
            action  = 'store', 
            dest    = 'uninstall_for_svc', 
            metavar = '<service>', 
            default = None)
        toolbox_mxg.add_argument(
            '--uninstall-tool', 
            help    = 'Uninstall a given tool',
            action  = 'store', 
            dest    = 'uninstall_tool', 
            metavar = '<tool-name>', 
            default = None)
        toolbox_mxg.add_argument(
            '--uninstall-all', 
            help    = 'Uninstall all tools in the toolbox',
            action  = 'store_true', 
            dest    = 'uninstall_all', 
            default = False)

        parameter = parser.add_argument_group(Output.colored('Parameter', attrs='bold'))
        parameter.add_argument(
            '--fast', 
            help    = 'Fast mode, disable prompts and manual post-install checks',
            action  = 'store_true', 
            dest    = 'fast_mode', 
            default = False)

        self.subparser = parser
        # Inside Mode, so ignore the first TWO argvs
        self.args = parser.parse_args(sys.argv[2:])


    #------------------------------------------------------------------------------------
    # Info Subcommand Parsing

    def info(self):
        """Arguments for subcommand Info"""

        self.mode = Mode.INFO

        parser = self.__create_subcmd_parser()
        info = parser.add_argument_group(Output.colored('Info', attrs='bold'))

        info_mxg = info.add_mutually_exclusive_group()
        info_mxg.add_argument(
            '--services', 
            help    = 'List supported services', 
            action  = 'store_true', 
            dest    = 'show_services', 
            default = False)
        info_mxg.add_argument(
            '--checks',
            help    = 'Show all the security checks for the given service',
            action  = 'store',
            dest    = 'show_checks',
            metavar = '<service>',
            default = None)
        info_mxg.add_argument(
            '--attack-profiles',
            help    = 'Show the attack profiles',
            action  = 'store',
            dest    = 'show_attack_profiles',
            nargs   = '?',
            metavar = '<service>',
            const   = 'all',
            default = None)
        info_mxg.add_argument(
            '--options',
            help    = 'Show all supported context-specific options',
            action  = 'store_true',
            dest    = 'show_specific_options',
            default = False)
        info_mxg.add_argument(
            '--products',
            help    = 'Show all supported products',
            action  = 'store_true',
            dest    = 'show_products',
            default = False)
        info_mxg.add_argument(
            '--http-auth-types',
            help    = 'List the supported HTTP authentication types',
            action  = 'store_true',
            dest    = 'show_http_auth_types',
            default = False)

        self.subparser = parser
        self.args = parser.parse_args(sys.argv[2:])


    #------------------------------------------------------------------------------------
    # Db Subcommand Parsing

    def db(self):
        """Arguments for subcommand Db"""
        self.mode = Mode.DB 

        #sys.argv = sys.argv[0:1]
        #self.args = parser.parse_args(sys.argv[2:])


    #------------------------------------------------------------------------------------
    # Attack Subcommand Parsing

    def attack(self):
        """Arguments for subcommand Attack"""
        self.mode = Mode.ATTACK 

        # todo:
        # option --reverse-dns-off
        #
        parser = self.__create_subcmd_parser()
        singletarget = parser.add_argument_group(
            Output.colored('Mode: Single target', attrs='bold'), 
            'Run security checks against one target.')

        singletarget.add_argument(
            '-t', '--target',
            help    = 'Target IP[:PORT] (default port if not specified) or URL',
            action  = 'store',
            dest    = 'target_ip_or_url',
            metavar = '<ip[:port] | url>',
            default = None)
        singletarget.add_argument(
            '-s', '--service',
            help    = 'Target service',
            action  = 'store',
            dest    = 'service',
            metavar = '<service>',
            default = None)
        singletarget.add_argument(
            '--add2db',
            help    = 'Add/update the target into a given mission scope in the database',
            action  = 'store',
            dest    = 'add',
            metavar = '<mission>',
            default = None)


        multitargets = parser.add_argument_group(
            Output.colored('Mode: Multiple targets from a mission scope', attrs='bold'),
            'Select targets from the scope of an existing mission.')

        multitargets.add_argument(
            '-m', '--mission',
            help    = 'Load targets from the specified mission',
            action  = 'store',
            dest    = 'mission',
            metavar = '<mission>',
            default = None)
        multitargets.add_argument(
            '-f', '--filter',
            help    = 'Set of conditions to select a subset of targets\n' \
                      '(e.g "ip=10.1.1.0/24,10.0.0.4;port=80,8000-8100;service=http")\n'\
                      'Available filter options: {opt}\n' \
                      'Several filters can be used (logical OR) by using the option ' \
                      'multiple times'.format(opt=', '.join(TARGET_FILTERS)),
            action  = 'append',
            dest    = 'filter',
            metavar = '<filter>',
            default = None)


        init = parser.add_argument_group(
            Output.colored('Target initialization', attrs='bold'))

        init.add_argument(
            '--reverse-dns',
            help    = 'Enable/disable reverse DNS lookup (default: ' \
                      'On for single target / Off for multiple)',
            choices = ['on', 'off'],
            default = None)

        init.add_argument(
            '--nmap-banner-grab', 
            help    = 'Enable/disable Nmap banner grabbing (default: ' \
                      'On for single target / Off for multiple)',
            choices = ['on', 'off'],
            default = None)


        selection = parser.add_argument_group(
            Output.colored('Attack configuration', attrs='bold'),
            'Select a subset of checks to run, either manually or by using a ' \
            'pre-defined attack profile.')

        selection_mxg = selection.add_mutually_exclusive_group()
        selection_mxg.add_argument(
            '--profile',
            help    = 'Use a pre-defined attack profile',
            action  = 'store',
            dest    = 'profile',
            metavar = '<profile>',
            default = None)
        selection_mxg.add_argument(
            '--cat-only', 
            help    = 'Run only checks in specified category(ies) (comma-separated)', 
            action  = 'store', 
            dest    = 'cat_only', 
            metavar = '<cat1,cat2...>', 
            default = None)
        selection_mxg.add_argument(
            '--cat-exclude', 
            help    = 'Run all checks except the ones in specified ' \
                      'category(ies) (comma-separated)',
            action  = 'store',
            dest    = 'cat_exclude',
            metavar = '<cat1,cat2...>',
            default = None)
        selection_mxg.add_argument(
            '--checks',
            help    = 'Run only the specified check(s) (comma-separated)',
            action  = 'store',
            dest    = 'checks',
            metavar = '<check1,check2...>',
            default = None) 


        running = parser.add_argument_group(
            Output.colored('Running option', attrs='bold'))

        running.add_argument(
            '--fast', 
            help    = 'Fast mode, disable prompts',
            action  = 'store_true', 
            dest    = 'fast_mode', 
            default = False)
        running.add_argument(
            '-d',
            help    = 'Enable debug mode', 
            action  = 'store_true',
            dest    = 'debug',
            default = False)


        bruteforce = parser.add_argument_group(
            Output.colored('Bruteforce options', attrs='bold'))

        bruteforce.add_argument(
            '--userlist',
            help    = 'List of usernames to use (instead of default lists)',
            action  = 'store',
            dest    = 'userlist',
            default = None)
        bruteforce.add_argument(
            '--passlist',
            help    = 'List of passwords to use (instead of default lists)',
            action  = 'store',
            dest    = 'passlist',
            default = None)
        bruteforce.add_argument(
            '--weblist',
            help    = 'Wordlist for web content discovery',
            action  = 'store',
            dest    = 'weblist',
            default = None)


        context = parser.add_argument_group(
            Output.colored('Context parameters', attrs='bold'),
            'Define manually some known information about the target(s).\n' \
            'In most cases, you do not have to use these parameters because Jok3r ' \
            'does its best\nto detect the context automatically, based on the results ' \
            'of various checks.')

        context.add_argument(
            '--cred', 
            help    = 'Credentials (username + password)', 
            action  = Store2or3Append,
            nargs   = '+',
            dest    = 'creds', 
            metavar = ('[<svc>[.<type>]] <user> <pass>',''))
        context.add_argument(
            '--user', 
            help    = 'Single username', 
            action  = Store1or2Append,
            nargs   = '+',
            dest    = 'users',
            metavar = ('[<svc>[.<type>]] <user>',''))
        context.add_argument(
            '--product',
            help    = 'Product',
            action  = 'append',
            dest    = 'products',
            metavar = '<type=name>',
            default = None)
        context.add_argument(
            '--option',
            help    = 'Specific option',
            action  = 'append',
            dest    = 'options',
            metavar = '<name=value>',
            default = None)


        self.subparser = parser
        self.args = parser.parse_args(sys.argv[2:])       
   

    #------------------------------------------------------------------------------------

    def check_args(self):
        """Main routine for arguments checking, dispatch to correct function"""
        
        if   self.mode == Mode.TOOLBOX :  return self.check_args_toolbox()
        elif self.mode == Mode.INFO    :  return self.check_args_info()
        elif self.mode == Mode.DB      :  return self.check_args_db()
        else                           :  return self.check_args_attack()


    #------------------------------------------------------------------------------------
    # Arguments checking for subcommand Toolbox

    def check_args_toolbox(self):
        """Check arguments for subcommand Toolbox"""

        service = self.args.show_toolbox_for_svc or \
                  self.args.install_for_svc      or \
                  self.args.update_for_svc       or \
                  self.args.uninstall_for_svc

        if len(sys.argv) == 2:
            self.subparser.print_help()
            return False

        # Check options with service name as parameter
        if service \
           and not self.settings.services.is_service_supported(service, multi=True):

            logger.error('Service "{service}" is not supported. ' \
                'Check "info --services".'.format(service=service.upper()))
            return False

        # Check option with tool name as parameter
        if self.args.uninstall_tool \
           and self.settings.toolbox.get_tool(self.args.uninstall_tool) is None:

            logger.error('Tool "{tool}" is not referenced inside the toolbox. ' \
                'Check "toolbox --show-all".'.format(tool=self.args.uninstall_tool))
            return False

        return True


    #------------------------------------------------------------------------------------
    # Arguments checking for subcommand Info

    def check_args_info(self):
        """Check arguments for subcommand Info"""

        service = self.args.show_checks or \
                  self.args.show_attack_profiles

        if len(sys.argv) == 2:
            self.subparser.print_help()
            return False

        # Check option with service name as parameter
        if service \
           and not self.settings.services.is_service_supported(service, multi=False):

            if self.args.show_attack_profiles and service == 'all':
                return True

            logger.error('Service "{service}" is not supported. ' \
                'Check "info --services".'.format(service=service.upper()))
            return False

        return True


    #------------------------------------------------------------------------------------
    # Arguments checking for subcommand Db

    def check_args_db(self):
        """Check arguments for subcommand Db"""
        return True


    #------------------------------------------------------------------------------------
    # Arguments checking for subcommand Attack

    def check_args_attack(self):
        """Check arguments for subcommand Attack"""

        status = True
        if self.args.target_ip_or_url and self.args.mission:
            logger.error('--target and --mission cannot be used at the same time')
            return False

        elif self.args.target_ip_or_url:
            status &= self.__check_args_attack_single_target()

        elif self.args.mission:
            status &= self.__check_args_attack_multi_targets()

        else:
            #logger.error('At least one target must be selected')
            self.subparser.print_help()
            return False

        if self.args.debug:
            logger.setLevel('DEBUG')
            logger.debug('Debug mode enabled')

        status &= self.__check_args_attack_single_target()
        status &= self.__check_args_attack_multi_targets()
        status &= self.__check_args_attack_bruteforce()
        status &= self.__check_args_attack_selection()

        return status

                
    def __check_args_attack_single_target(self):
        """Check arguments for subcommand Attack > Single target options"""

        target = self.args.target_ip_or_url

        # Target specified is an URL
        if target.lower().startswith('http://') or target.lower().startswith('https://'):
            self.args.target_mode = TargetMode.URL

            if self.args.service and self.args.service.lower() != 'http':
                logger.warning('URL only supported for HTTP service. ' \
                    'Automatically switch to HTTP')

            elif not self.args.service:
                logger.info('URL given as target, targeted service is HTTP')

            self.args.service = 'http'
            self.args.target_port = WebUtils.get_port_from_url(target)

        # Target specified is IP[:PORT] or HOSTNAME[:PORT]               
        else:
            self.args.target_mode = TargetMode.IP # Actually can be either IP or Hostname
            self.args.target_port = None
            s = target.split(':')
            self.args.target_ip_or_url = s[0]

            # Extract port 
            if len(s) == 2:
                self.args.target_port = int(s[1])
                if not (0 <= self.args.target_port <= 65535):
                    logger.error('Target port is not valid. Must be in the' \
                        'range [0-65535]')
                    return False

            elif len(s) > 2:
                logger.error('Incorrect target format. Must be either IP[:PORT] or ' \
                    'an URL')
                return False

            # Check or define targeted service and port
            if self.args.service:

                # Check if service is supported
                if not self.settings.services.is_service_supported(
                    self.args.service, multi=False):

                    logger.error('Service "{service}" is not supported. ' \
                        'Check "info --services".'.format(
                            service=self.args.service.upper()))
                    return False

                # Try to get default port if it is not specified
                if not self.args.target_port:
                    self.args.target_port = self.settings.services.get_default_port(
                        self.args.service)

                    if self.args.target_port:
                        logger.info('Default port for service {service} will be used: ' \
                            '{port}/{proto}'.format(
                                service = self.args.service,
                                port    = self.args.target_port,
                                proto   = self.settings.services.get_protocol(
                                    self.args.service)))

                    else:
                        logger.error('Target port is not specified and no default port' \
                            ' can be found for the service {service}'.format(
                                service=self.args.service))
                        return False

            # Try to get default service for provided port if not specified
            else:

                if not self.args.target_port:
                    logger.error('Target port and/or service must be specified')
                    return False

                else:
                    self.args.service = self.settings.services.get_service_from_port(
                        self.args.target_port)

                    if not self.args.service:
                        logger.error('Cannot automatically determine the target ' \
                            'service for port {port}/tcp, use --target IP:PORT ' \
                            'syntax'.format(port=self.args.target_port))
                        return False

                    logger.info('Automatic service detection based on target port: ' \
                        '{service}'.format(service=self.args.service))

        return True


    def __check_args_attack_multi_targets(self):
        """Check arguments for subcommand Attack > Multi targets options"""

        # Check filter(s)
        # There can be several --filter, logical or is applied between them
        if self.args.filter:
            filter_ = Filter(FilterOperator.OR)

            for c in self.args.filter:
                combo = Filter(FilterOperator.AND)
                for cond in c.split(';'):
                    if cond.count('=') != 1:
                        logger.error('Filter syntax incorrect')
                        return False

                    name, val = cond.split('=')
                    name = name.lower()
                    if name not in TARGET_FILTERS.keys():
                        logger.error('Filter option {filter} is not supported. ' \
                            'Available options are: {options}'.format(
                                filter=name, options=', '.join(TARGET_FILTERS.keys())))
                        return False

                    try:
                        condition = Condition(val.split(','), TARGET_FILTERS[name])
                    except Exception as e:
                        logger.error('Filter exception: {msg}'.format(e))
                        return False

                    combo.add_condition(condition)

            filter_.add_condition(combo)

            self.args.filters_combined = filter_

        else:
            self.args.filters_combined = None

        return True


    def __check_args_attack_selection(self):
        """Check arguments for subcommand Attack > Checks selection options"""

        # Selection of categories of checks to run or to exclude
        categories = self.args.cat_only or self.args.cat_exclude
        if categories:
            categories = categories.split(',')
            for cat in categories:
                if cat not in self.settings.services.list_all_categories():
                    logger.error('Category {cat} does not exist. ' \
                        'Check "info --categories".'.format(cat=cat))
                    return False

            # Store as list
            if self.args.cat_only:
                self.args.cat_only = categories
            elif self.args.cat_exclude:
                self.args.cat_exclude = categories


        # Selection of checks to run
        elif self.args.checks:
            checks = self.args.checks.split(',')
            for check in checks:
                if not self.settings.services.is_existing_check(check):
                    logger.error('Check {check} does not exist. ' \
                        'Check "info --checks <service>".'.format(check=check))
                    return False

            # Store as list
            self.args.checks = checks


        # Attack profile
        elif self.args.profile:
            profile = self.settings.attack_profiles.get(self.args.profile.lower())
            if not profile:
                logger.error('Attack profile {profile} does not exist. ' \
                    'Check "info --attack-profiles'.format(
                        profile=self.args.profile))
                return False

            elif self.args.target_ip_or_url \
                 and not profile.is_service_supported(self.args.service):

                logger.error('Attack profile {profile} is not supported for ' \
                    'service {service}'.format(
                        profile=self.args.profile, service=self.args.service))
                return False

        return True


    def __check_args_attack_bruteforce(self):
        """Check arguments for subcommand Attack > Bruteforce options"""

        for f in self.args.userlist, self.args.passlist, self.args.weblist:
            if f:
                if not FileUtils.can_read(f):
                    logger.error('File {file} does not exist or cannot be read'.format(
                        file=f))
                    return False

        return True


    def __check_args_attack_context(self):
        """Check arguments for subcommand Attack > Context parameters"""

        status = True

        status &= self.__check_args_attack_context_cred()
        status &= self.__check_args_attack_context_user()
        status &= self.__check_args_attack_context_product()
        status &= self.__check_args_attack_context_option()

        return status


    def __check_args_attack_context_cred(self):
        """
        Check arguments for subcommand Attack > Context parameters > --cred
        Syntax: --cred [<svc>[.<type>]] <user> <pass>

        If some credentials submitted, self.args.creds is turned into a list of
        dicts, one dict per cred.
        """

        if not self.args.creds:
            return True

        creds = list()
        for cred in self.args.creds:
            current_cred = {
                'service'  : None,
                'auth_type': None, # relevant for HTTP
                'username' : None, 
                'password' : None
            }

            # When format is: <svc>[.<type>] <user> <pass>
            if len(cred) == 3:
                if '.' in cred[0]:
                    svc, auth_type = cred[0].split('.', maxsplit=1)
                    svc = svc.lower()
                    if svc != 'http':
                        logger.error('Auth-type in --cred is only supported with ' \
                            'HTTP. Syntax: --cred http.<auth-type> <username> ' \
                            '<password>')
                        return False

                    elif not self.settings.services.is_valid_auth_type(auth_type):
                        logger.error('Invalid authentication type provided in --cred. ' \
                            'Check "info --list-http-auth".')
                        return False        

                    current_cred['auth_type'] = auth_type

                else:
                    svc = cred[0].lower()
                    if not self.settings.services.is_service_supported(svc):
                        logger.error('Service "{svc}" in --cred is not ' \
                            'supported'.format(svc=svc))
                        return False

                if self.args.service and self.args.service != svc:
                    logger.error('Single target mode selected but targeted service ' \
                        '({tgt_svc}) is different from service specified in --cred ' \
                        '({cred_svc})'.format(tgt_svc=self.args.service, cred_svc=svc))
                    return False

                current_cred['service']  = svc
                current_cred['username'] = cred[1]
                current_cred['password'] = cred[2] 

            # When format is simply: <user> <pass>
            # Accepted only in single target mode
            else:
                if self.args.service:
                    current_cred['service'] = self.args.service
                else:
                    logger.error('Service must be specified in --cred in multi targets' \
                        'mode. Syntax: --cred <service> <user> <pass>')
                    return False
                current_cred['username'] = cred[0]
                current_cred['password'] = cred[1]

            creds.append(current_cred)

        # Turn self.args.creds into a list of dict, one dict per cred
        self.args.creds = creds
        return True


    def __check_args_attack_context_user(self):
        """
        Check arguments for subcommand Attack > Context parameters > --user
        Syntax: --user [<svc>[.<type>]] <user>

        If some usernames submitted, self.args.users is turned into a list of
        dicts, one dict per user.
        """

        if not self.args.users:
            return True

        users = list()
        for user in self.args.users:
            current_user = {
                'service'   : None,
                'auth_type' : None, 
                'username'  : None
            }

            # When format is: <svc>[.<type>] <user>
            if len(user) == 2:
                if '.' in user[0]:
                    svc, auth_type = user[0].split('.', maxsplit=1)
                    svc = svc.lower()
                    if svc != 'http':
                        logger.error('Auth-type in --user is only supported with ' \
                            'HTTP. Syntax: --user http.<auth-type> <username>')
                        return False

                    elif not self.settings.services.is_valid_auth_type(auth_type):
                        logger.error('Invalid authentication type provided in --user. ' \
                            'Check "info --list-http-auth".')
                        return False

                    current_user['auth_type'] = auth_type

                else:
                    svc = user[0].lower()
                    if not self.settings.services.is_service_supported(svc):
                        logger.error('Service "{svc}" in --user is not ' \
                            'supported'.format(svc=svc))
                        return False

                if self.args.service and self.args.service != svc:
                    logger.error('Single target mode selected but targeted service ' \
                        '({tgt_svc}) is different from service specified in --user ' \
                        '({user_svc})'.format(tgt_svc=self.args.service, user_svc=svc))
                    return False

                current_user['service']  = svc
                current_user['username'] = user[1]

            # When format is simply: <user>
            # Accepted only in single target mode
            else:
                if self.args.service:
                    current_user['service'] = self.args.service
                else:
                    logger.error('Service must be specified in --user in multi targets' \
                        'mode. Syntax: --user <service> <user>')
                    return False

                current_user['username'] = user[0]

            users.append(current_user)

        # Turn self.args.users into a list of dict, one dict per username
        self.args.users = users
        return True


    def __check_args_attack_context_product(self):
        """
        Check arguments for subcommand Attack > Context parameters > --product
        Syntax: --product <type=name>

        If some products submitted, self.args.products is turned into a dict
        {type: name}
        """

        if not self.args.products:
            return True

        products = dict()
        for product in self.args.products:
            if '=' in product:
                type_, name = product.split('=', maxsplit=1)

                if not self.settings.services.is_product_type_supported(
                        type_, service=self.args.service or None):
                    logger.error('The product type "{type}" submitted is not ' \
                        'supported. Check "info --products".'.format(type=type_))
                    return False

                elif not self.settings.services.is_product_name_supported(type_, name):
                    logger.error('The product name "{name}" submitted for ' \
                        'type={type} is not supported. Check "info --products".'.format(
                            name=name, type=type_))
                    return False

                elif type_ in products.keys():
                    logger.error('Same product type "{type}" is defined several ' \
                        'times'.format(type=type_))
                    return False

                else:
                    products[type_] = name

            else:
                logger.error('Invalid syntax for --product. Must be: <type=name>')
                return False

        self.args.products = products
        return True


    def __check_args_attack_context_option(self):
        """
        Check arguments for subcommand Attack > Context parameters > --option
        Syntax: --option <name=value>

        If some options submitted, self.args.options is turned into a dict
        {name: value}
        """

        if not self.args.options:
            return True

        options = dict()
        for option in self.args.options:
            if '=' in option:
                name, value = map(lambda x: x.lower(), option.split('=', maxsplit=1))

                if not self.settings.services.is_specific_option_name_supported(
                        name, service=self.args.service or None):
                    logger.error('The specific option name "{name}" is not ' \
                        'supported. Check "info --options".'.format(name=name))
                    return False

                elif not self.settings.services.is_specific_option_value_supported(
                        name, value):
                    logger.error('The value for the specific option named "{name}" is ' \
                        'not valid. Check "info --options".'.format(name=name))
                    return False

                else:
                    options[name] = value

        self.args.options = options


