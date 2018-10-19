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
from lib.utils.WebUtils import WebUtils
from lib.output.Logger import logger
from lib.output.Output import Output


class ArgumentsParser:

    formatter_class = lambda prog: LineWrapRawTextHelpFormatter(prog, max_help_position=ARGPARSE_MAX_HELP_POS)

    def __init__(self, settings):
        self.settings = settings
        self.mode     = None
        self.args     = None

        parser = argparse.ArgumentParser(usage=USAGE, formatter_class=ArgumentsParser.formatter_class)
        parser.add_argument('command', help=argparse.SUPPRESS)

        # https://chase-seibert.github.io/blog/2014/03/21/python-multilevel-argparse.html
        # parse_args defaults to [1:] for args, but need to exclude the rest of the args too
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            logger.error('Unrecognized command')
            parser.print_help()
            raise ArgumentsException()

        self.subparser = None
        # Use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

        if not self.check_args():
            raise ArgumentsException()


    def __create_subcmd_parser(self):
        subcmd = {
            Mode.TOOLBOX : 'toolbox',
            Mode.INFO    : 'info',
            Mode.DB      : 'db',
            Mode.ATTACK  : 'attack'
        }.get(self.mode)
        return argparse.ArgumentParser(usage='python3 jok3r.py {subcmd} <args>'.format(subcmd=subcmd),
                                       formatter_class=ArgumentsParser.formatter_class) 


    def toolbox(self):
        """
        Modes mode Toolbox
        """
        self.mode = Mode.TOOLBOX

        parser = self.__create_subcmd_parser()
        toolbox = parser.add_argument_group(Output.colored('Toolbox management', attrs='bold'), 
            'Tools are classified by services they can target into the toolbox. Tools that may be used ' +
            'against various\ndifferent services are grouped under the name "multi".')

        toolbox_mxg = toolbox.add_mutually_exclusive_group()
        toolbox_mxg.add_argument('--show', 
                                 help    = 'Show toolbox content for a given service', 
                                 action  = 'store', 
                                 dest    = 'show_toolbox_for_svc', 
                                 metavar = '<service>', 
                                 default = None)
        toolbox_mxg.add_argument('--show-all', 
                                 help    = 'Show full toolbox content', 
                                 action  = 'store_true', 
                                 dest    = 'show_toolbox_all', 
                                 default = False)
        toolbox_mxg.add_argument('--install', 
                                 help    = 'Install the tools for a given service', 
                                 action  = 'store', 
                                 dest    = 'install_for_svc', 
                                 metavar = '<service>', 
                                 default = None)
        toolbox_mxg.add_argument('--install-all', 
                                 help    = 'Install all the tools in the toolbox',
                                 action  = 'store_true', 
                                 dest    = 'install_all', 
                                 default = False)
        toolbox_mxg.add_argument('--update', 
                                 help    = 'Update the installed tools for a given service',
                                 action  = 'store', 
                                 dest    = 'update_for_svc', 
                                 metavar = '<service>', 
                                 default = None)
        toolbox_mxg.add_argument('--update-all',
                                 help    = 'Update all installed tools in the toolbox',
                                 action  = 'store_true', 
                                 dest    = 'update_all', 
                                 default = False)
        toolbox_mxg.add_argument('--uninstall', 
                                 help    = 'Uninstall the tools for a given service',
                                 action  = 'store', 
                                 dest    = 'uninstall_for_svc', 
                                 metavar = '<service>', 
                                 default = None)
        toolbox_mxg.add_argument('--uninstall-tool', 
                                 help    = 'Uninstall a given tool',
                                 action  = 'store', 
                                 dest    = 'uninstall_tool', 
                                 metavar = '<tool-name>', 
                                 default = None)
        toolbox_mxg.add_argument('--uninstall-all', 
                                 help    = 'Uninstall all tools in the toolbox',
                                 action  = 'store_true', 
                                 dest    = 'uninstall_all', 
                                 default = False)

        toolbox.add_argument('--fast', 
                             help    = 'Fast mode, disable prompts and post-install checks',
                             action  = 'store_true', 
                             dest    = 'fast_mode', 
                             default = False)

        self.subparser = parser
        # Inside Mode, so ignore the first TWO argvs
        self.args = parser.parse_args(sys.argv[2:])


    def info(self):
        """
        Modes mode Info
        """
        self.mode = Mode.INFO

        parser = self.__create_subcmd_parser()
        info = parser.add_argument_group(Output.colored('Info', attrs='bold'))

        info_mxg = info.add_mutually_exclusive_group()
        info_mxg.add_argument('--services', 
                              help    = 'List supported services', 
                              action  = 'store_true', 
                              dest    = 'show_services', 
                              default = False)
        info_mxg.add_argument('--options',
                              help    = 'List supported context-specific options',
                              action  = 'store_true',
                              dest    = 'show_specific_options',
                              default = False)
        info_mxg.add_argument('--http-auth-types',
                              help    = 'List the supported HTTP authentication types',
                              action  = 'store_true',
                              dest    = 'show_http_auth_types',
                              default = False)
        info_mxg.add_argument('--checks',
                              help    = 'List all the checks for the given service',
                              action  = 'store',
                              dest    = 'show_checks',
                              metavar = '<service>',
                              default = None)

        self.subparser = parser
        self.args = parser.parse_args(sys.argv[2:])


    def db(self):
        """
        Modes mode Database
        """
        self.mode = Mode.DB 
        # localdb = parser.add_argument_group('Database',
        #     'The local database stores the missions, all information related to the targets, as well as '+
        #     'the results of the checks that have been runned')

        #sys.argv = sys.argv[0:1]
        #self.args = parser.parse_args(sys.argv[2:])


    def attack(self):
        """
        Modes mode Attack
        """
        self.mode = Mode.ATTACK 

        parser = self.__create_subcmd_parser()
        singletarget = parser.add_argument_group(Output.colored('Single target', attrs='bold'), 
            'Quickly define a target to run checks against it.')

        singletarget.add_argument('-t', '--target',
                                  help    = 'Target IP[:PORT] (default port if not specified) or URL',
                                  action  = 'store',
                                  dest    = 'target_ip_or_url',
                                  metavar = '<ip[:port] | url>',
                                  default = None)
        singletarget.add_argument('-s', '--service',
                                  help    = 'Target service',
                                  action  = 'store',
                                  dest    = 'service',
                                  metavar = '<service>',
                                  default = None)
        singletarget.add_argument('--add',
                                  help    = 'Add/update the target into a given mission scope',
                                  action  = 'store',
                                  dest    = 'add',
                                  metavar = '<mission>',
                                  default = None)
        singletarget.add_argument('--disable-banner-grab',
                                  help    = 'Disable banner grabbing with Nmap at start',
                                  action  = 'store_true',
                                  default = False)

        multitargets = parser.add_argument_group(Output.colored('Multiple targets from a mission scope', attrs='bold'),
            'Select targets from the scope of an existing mission.')

        multitargets.add_argument('-m', '--mission',
                                  help    = 'Load targets from the specified mission',
                                  action  = 'store',
                                  dest    = 'mission',
                                  metavar = '<mission>',
                                  default = None)
        multitargets.add_argument('-f', '--filter',
                                  help    = 'Set of conditions to select a subset of targets\n' +
                                            '(e.g "ip=192.168.1.0/24,10.0.0.4;port=80,8000-8100;service=http").\n' +
                                            'Available filter options: {opt}\n'.format(opt=', '.join(TARGET_FILTERS)) +
                                            'Several sets can be combined (logical OR) by using the option multiple times',
                                  action  = 'append',
                                  dest    = 'filter',
                                  metavar = '<filter>',
                                  default = None)

        selection = parser.add_argument_group(Output.colored('Selection of checks', attrs='bold'),
            'Select only some categories/checks to run against the target(s).')
        selection_mxg = selection.add_mutually_exclusive_group()
        selection_mxg.add_argument('--cat-only', 
                                   help    = 'Run only tools in specified category(ies) (comma-separated)', 
                                   action  = 'store', 
                                   dest    = 'cat_only', 
                                   metavar = '<cat1,cat2...>', 
                                   default = None)
        selection_mxg.add_argument('--cat-exclude', 
                                   help    = 'Do not run tools in specified category(ies) (comma-separated)',
                                   action  = 'store',
                                   dest    = 'cat_exclude',
                                   metavar = '<cat1,cat2...>',
                                   default = None)
        selection_mxg.add_argument('--checks',
                                   help    = 'Run only the specified check(s) (comma-separated)',
                                   action  = 'store',
                                   dest    = 'checks',
                                   metavar = '<check1,check2...>',
                                   default = None) 

        running = parser.add_argument_group(Output.colored('Running option', attrs='bold'))
        running.add_argument('--fast', 
                             help    = 'Fast mode, disable prompts',
                             action  = 'store_true', 
                             dest    = 'fast_mode', 
                             default = False)

        auth = parser.add_argument_group(Output.colored('Authentication', attrs='bold'), 
            'Define authentication option if some credentials or single usernames are known.\n' \
            'Options can be used multiple times. For multiple targets, the service for which \n' \
            'the creds/users will be used should be specified.')
        auth.add_argument('--cred', 
                          help    = 'Credentials (username + password)', 
                          action  = Store2or3Append,
                          nargs   = '+',
                          dest    = 'creds', 
                          metavar = ('[<svc>[.<type>]] <user> <pass>',''))
        auth.add_argument('--user', 
                          help    = 'Single username', 
                          action  = Store1or2Append,
                          nargs   = '+',
                          dest    = 'users',
                          metavar = ('[<svc>[.<type>]] <user>',''))

        specific = parser.add_argument_group(Output.colored('Context-specific options', attrs='bold'), 
            'Define manually some known info about the target(s).')

        specific.add_argument('specific', 
                              help    = 'Context-specific options, format name=value (space-separated)', 
                              metavar = '<opt1=val1 opt2=val2 ...>', 
                              nargs   = '*')

        self.subparser = parser
        self.args = parser.parse_args(sys.argv[2:])       
   

    def check_args(self):
        """
        Main routine for arguments checking, dispatch to correct function
        """
        
        if   self.mode == Mode.TOOLBOX :  return self.check_args_toolbox()
        elif self.mode == Mode.INFO    :  return self.check_args_info()
        elif self.mode == Mode.DB      :  return self.check_args_db()
        else                           :  return self.check_args_attack()


    def check_args_toolbox(self):
        """
        Check arguments for mode TOOLBOX
        """
        service = self.args.show_toolbox_for_svc or \
                  self.args.install_for_svc      or \
                  self.args.update_for_svc       or \
                  self.args.uninstall_for_svc

        if len(sys.argv) == 2:
            self.subparser.print_help()
            return False

        if service is not None and not self.settings.services.is_service_supported(service):
            logger.error('Service "{service}" is not supported. Check "info --services".'.format(
                service=service.lower()))
            return False

        if self.args.uninstall_tool is not None and \
           self.settings.toolbox.get_tool(self.args.uninstall_tool) is None:
            logger.error('Tool "{tool}" is not referenced inside the toolbox. ' \
                'Check "toolbox --show-all".'.format(tool=self.args.uninstall_tool))
            return False

        return True


    def check_args_info(self):
        """
        Check arguments for mode INFO
        """
        service = self.args.show_checks

        if len(sys.argv) == 2:
            self.subparser.print_help()
            return False

        if service is not None and not self.settings.services.is_service_supported(service, multi=False):
            logger.error('Service "{service}" is not supported. Check "info --services".'.format(
                service=service.lower()))
            return False

        return True


    def check_args_db(self):
        """
        Check arguments for mode DB
        """
        return True


    def check_args_attack(self):
        """
        Check arguments for mode ATTACK
        """
        status = True
        if self.args.target_ip_or_url and self.args.mission:
            logger.error('--target and --mission cannot be used at the same time')
            return False

        elif self.args.target_ip_or_url is not None:
            status &= self.__check_args_attack_single_target()

        elif self.args.mission is not None:
            status &= self.__check_args_attack_multi_targets()

        else:
            #logger.error('At least one target must be selected')
            self.subparser.print_help()
            return False

        status &= self.__check_args_attack_selection()
        status &= self.__check_args_attack_authentication()
        status &= self.__check_args_attack_specific_options()

        return status

                
    def __check_args_attack_single_target(self):
        """
        Check arguments for ATTACK > Single target options
        """
        target = self.args.target_ip_or_url


        # Target specified is an URL
        if target.lower().startswith('http://') or target.lower().startswith('https://'):
            self.args.target_mode = TargetMode.URL
            if self.args.service is not None and self.args.service.lower() != 'http':
                logger.warning('URL only supported for HTTP service. Automatically switch to HTTP')
            elif self.args.service is None:
                logger.info('URL given as target, targeted service is HTTP')
            self.args.service = 'http'
            self.args.target_port = WebUtils.get_port_from_url(target)

        # Target specified is IP[:PORT] or HOSTNAME[:PORT]               
        else:
            self.args.target_mode = TargetMode.IP # Actually can be either IP or Hostname
            self.args.target_port = None
            s = target.split(':')
            self.args.target_ip_or_url = s[0]
            if len(s) == 2:
                self.args.target_port = int(s[1])
                if not (0 <= self.args.target_port <= 65535):
                    logger.error('Target port is not valid. Must be in the range [0-65535]')
                    return False
            elif len(s) > 2:
                logger.error('Incorrect target format. Must be either IP[:PORT] or an URL')
                return False

            # Check or define targeted service and port
            if self.args.service is not None:
                if not self.settings.services.is_service_supported(self.args.service):
                    logger.error('Service "{service}" is not supported. Check "info --services".'.format(
                        service=self.args.service.lower()))
                    return False

                # Try to get default port if it is not specified
                if self.args.target_port is None:
                    self.args.target_port = self.settings.services.get_default_port(self.args.service)
                    if self.args.target_port is not None:
                        logger.info('Default port for service {service} will be used: {port}/{proto}', format(
                            service = self.args.service,
                            port    = self.args.target_port,
                            proto   = self.settings.services.get_protocol(self.args.service)))
                    else:
                        logger.error('Target port is not specified in command-line and no default port ' \
                            'can be found for the service {service}'.format(service=self.args.service))
                        return False
            else:
                # If no service specified, try to get the default service for the provided port
                if self.args.target_port is None:
                    logger.error('Target port and/or service must be specified')
                    return False
                else:
                    self.args.service = self.settings.services.get_service_from_port(self.args.target_port)
                    if self.args.service is None:
                        logger.error('Cannot automatically determine the target service for port ' \
                            '{port}/tcp, use --target IP:PORT syntax'.format(port=self.args.target_port))
                        return False
                    logger.info('Automatic service detection based on target port: {service}'.format(
                        service=self.args.service))

        return True


    def __check_args_attack_multi_targets(self):
        """
        Check arguments for ATTACK > Multi targets options
        """
        if self.args.filter is not None:
            # There can be several --filter, logical or is applied between them
            filter_ = Filter(FilterOperator.OR)
            for c in self.args.filter:
                combo = Filter(FilterOperator.AND)
                for cond in c.split(';'):
                    if cond.count('=') != 1:
                        logger.error('Filter syntax incorrect')
                        return False
                    name, val = cond.split('=')
                    if name not in TARGET_FILTERS.keys():
                        logger.error('Filter option {filter} is not supported. Available options ' \
                            'are: {options}'.format(filter=name, options=', '.join(TARGET_FILTERS.keys())))
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
        """
        Check arguments for ATTACK > Check Selection options
        """
        # Selection of categories of checks to run or to exclude
        categories = self.args.cat_only or self.args.cat_exclude
        if categories is not None:
            categories = categories.split(',')
            for cat in categories:
                if cat not in self.settings.services.list_all_categories():
                    logger.error('Category {cat} does not exist. Check "info --categories".'.format(cat=cat))
                    return False

            if self.args.cat_only:
                self.args.cat_only = list(set(categories)) # will contain the list of categories to run
            else:
                self.args.cat_only = list(set(self.settings.services.list_all_categories()).difference(set(categories)))

        # Selection of checks to run
        elif self.args.checks is not None:
            self.args.checks = self.args.checks.split(',') # will contain the list of checks to run
            for check in self.args.checks:
                if not self.settings.services.is_existing_check(check):
                    logger.error('Check {check} does not exist. Check "info --checks <service>".'.format(check=check))
                    return False

        return True


    def __check_args_attack_authentication(self):
        """
        Check arguments for ATTACK > Authentication options
        """
        # Credentials submitted (username+password)
        if self.args.creds:
            creds = list()
            for cred in self.args.creds:
                current_cred = {
                    'service'  : None, # if stays at None, means for all services
                    'auth_type': None, # relevant for HTTP
                    'username' : None, 
                    'password' : None
                }
                if len(cred) == 3:
                    if '.' in cred[0]:
                        svc, auth_type = cred[0].split('.')
                        svc = svc.lower()
                        if svc != 'http':
                            logger.error('Auth-type in --cred is only supported with HTTP. ' \
                                'Syntax: --cred http.<auth-type> <username> <password>')
                            return False
                        elif not self.settings.services.is_valid_authentication_type(auth_type, svc):
                            logger.error('Invalid authentication type provided in --cred. Check "info --list-http-auth".')
                            return False        
                        current_cred['auth_type'] = auth_type
                    else:
                        svc = cred[0].lower()
                        if not self.settings.services.is_service_supported(svc):
                            logger.error('Service "{svc}" in --cred is not supported'.format(svc=svc))
                            return False
                    current_cred['service']  = svc
                    current_cred['username'] = cred[1]
                    current_cred['password'] = cred[2] 

                else:
                    current_cred['username'] = cred[0]
                    current_cred['password'] = cred[1]

                creds.append(current_cred)
            # Turn self.args.creds into a list of dict, one dict per cred
            self.args.creds = creds


        # Single usernames (password unknown)
        if self.args.users:
            users = list()
            for user in self.args.users:
                current_user = {
                    'service'   : None,
                    'auth_type' : None, 
                    'username'  : None
                }
                if len(user) == 2:
                    if '.' in user[0]:
                        svc, auth_type = user[0].split('.')
                        svc = svc.lower()
                        if svc != 'http':
                            logger.error('Auth-type in --user is only supported with HTTP. ' \
                                'Syntax: --user http.<auth-type> <username>')
                            return False
                        elif not self.settings.services.is_valid_authentication_type(auth_type, svc):
                            logger.error('Invalid authentication type provided in --cred. Check "info --list-http-auth".')
                            return False        
                        current_user['auth_type'] = auth_type
                    else:
                        svc = cred[0].lower()
                        if not self.settings.services.is_service_supported(svc):
                            logger.error('Service "{svc}" in --user is not supported'.format(svc=svc))
                            return False
                    current_user['service']  = svc
                    current_user['username'] = user[1]

                else:
                    current_user['username'] = cred[0]

                users.append(current_user)
            # Turn self.args.users into a list of dict, one dict per username
            self.args.users = users

        return True


    def __check_args_attack_specific_options(self):
        """
        Check arguments for ATTACK > Specific Options
        """
        specific_options = dict()
        for opt in self.args.specific:
            if opt.count('=') != 1:
                logger.error('Incorrect syntax for context-specific options. Must be name=value and space-separated.')
                return False
            name, value = map(lambda x: x.lower(), opt.split('='))
            if len(value) == 0:
                logger.error('Context-specific option value cannot be empty')
                return False
            if not self.settings.services.is_specific_option_name_supported(name, service=self.args.service or None):
                logger.error('Context-specific option named "{opt}"" is not supported. Check "info --options"'.format(opt=name))
                return False
            if not self.settings.services.is_specific_option_value_supported(name, value):
                logger.error('Value for context-specific option "{opt}" is not valid. Check "info --options"'.format(opt=name))
                return False
            specific_options[name] = value

        self.args.specific = specific_options # dict of submitted context-specific options
        return True
