# -*- coding: utf-8 -*-
###
### Core > Settings 
###
#
# toolbox.conf:
# -------------
# For each tool registered inside toolbox:
#   [tool_name]
#   name           = name to display (mandatory)
#   description    = short text describing the tool (mandatory)
#   target_service = targeted service or "multi" (mandatory)
#   install        = installation command-line (optional)
#   update         = update command-line (optional)
#   check_command  = command to run to check for correct install (usually run tool without args) (optional)
#
# _install_status.conf:
# ---------------------
# For each supported service + "multi":
#   [target_service]
#   <tool_name>    = False if not installed, datetime of last install/update otherwise
#
# <service_name>.conf (one config file per service):
# --------------------------------------------------
# [config]
# default_port     = [0-65535] (mandatory)
# protocol         = tcp|udp (mandatory)
# categories       = list of categories for classifying checks ([a-z0-9_-]) (mandatory)
# auth_types       = list of authentication types, relevant only for HTTP ([a-z0-9_-]) (optional)
# 
# [specific_options]
# <option_name ([a-z0-9_-])> = boolean:default_value|list|var 
#       (for boolean, default value can be added, True or False. False by default)
#
# [supported_list_options] (may not be present if no option of type list)
# For each option of type "list":
#   supported_<option_name> = list of supported values for the option ([a-z0-9_-])
#
# For each check:
#   [check_<check_name>]
#   name           = display name (mandatory) 
#   category       = category inside which this check is classified (mandatory)
#   description    = short text describing the check (mandatory)
#   tool           = tool_name of the tool to use
#   For each command (there must be at least one command):
#       command_<command_number> = command-line for the check, multiple tags supported (see Command.py)
#       context_<command_number> = context that must be met to run the command, dictionary syntax (optional)
#   postrun        = method from smartmodules to run after the command (optional)
#
import ast
import traceback
import configparser
from datetime import datetime
from collections import defaultdict

from lib.core.Check import Check
from lib.core.Command import Command
from lib.core.Config import *
from lib.core.Constants import *
from lib.core.Context import Context
from lib.core.Exceptions import SettingsException
from lib.core.ServiceChecks import ServiceChecks
from lib.core.ServicesConfig import ServicesConfig
from lib.core.Tool import Tool
from lib.core.Toolbox import Toolbox
from lib.output.Logger import logger
from lib.utils.DefaultConfigParser import DefaultConfigParser
from lib.utils.FileUtils import FileUtils
from lib.utils.StringUtils import StringUtils


class Settings:
    """
    Class used for parsing settings files:
        - toolbox.conf         : File storing configuration about all tools
        - <service_name>.conf  : Each supported service has a corresponding .conf file
        - _install_status.conf : Store install status for each tool & last update if installed
    """

    def __init__(self):
        """
        :raises SettingsException:
        """
        self.config_parsers = dict() # dict of DefaultConfigParser indexed by filename
        self.toolbox        = None   # Receives Toolbox object
        self.services       = None   # Receives ServicesConfig object

        # Check directory and presence of *.conf files
        if not FileUtils.is_dir(SETTINGS_DIR):
            raise SettingsException('Configuration directory ({dir}) does not exist'.format(dir=SETTINGS_DIR))
        files = FileUtils.list_directory(SETTINGS_DIR)
        for f in files:
            if not FileUtils.check_extension(f, CONF_EXT):
                files.remove(f)

        if not files:
            raise SettingsException('Configuration directory ({dir}) does not store any *.conf file'.format(
                dir=SETTINGS_DIR))

        if not self.__check_presence_mandatory_files(files):
            raise SettingsException('Missing mandatory settings file in the directory "{dir}"'.format(
                    dir=SETTINGS_DIR, filename=f))

        # Parse settings files, add tools inside toolbox and create scan configs
        self.__parse_all_conf_files(files)
        self.__create_toolbox()
        self.__create_all_services_checks()
    

    def __check_presence_mandatory_files(self, files):
        """
        Check if following mandatory files are present in settings directory:
            - toolbox.conf
            - __install_status.conf
        :param files: List of files in settings directory
        """
        mandatory_files = [ 
            TOOLBOX_CONF_FILE + CONF_EXT, 
            INSTALL_STATUS_CONF_FILE + CONF_EXT
        ]
        for f in mandatory_files:
            if f not in files: return False
        return True


    def __parse_all_conf_files(self, files):
        """
        Parse all *.conf files into the settings directory.
        Initialize ServicesConfig object with list of supported services
        :param files: List of files in settings directory
        :return: None
        """
        list_services = list()
        for f in files:
            name = FileUtils.remove_ext(f).lower().strip()
            if name not in (INSTALL_STATUS_CONF_FILE, TOOLBOX_CONF_FILE):
                list_services.append(name)

            full_path = FileUtils.concat_path(SETTINGS_DIR, f)
            self.config_parsers[name] = DefaultConfigParser()
            self.config_parsers[name].read(full_path, 'utf8') # utf8 to avoid encoding issues

        list_services.append('multi') # Add support for special "multi" service
        self.services = ServicesConfig(list_services)


    def __create_toolbox(self):
        """
        Create the toolbox
        :return: None
        """
        self.toolbox = Toolbox(self, self.services.list_services(multi=True))
        for section in self.config_parsers[TOOLBOX_CONF_FILE].sections():
            newtool = self.__create_tool(section)
            if newtool is not None:
                if not self.toolbox.add_tool(newtool):
                    logger.warning('[{filename}{ext} | Section "{section}"] Unable to add tool "{tool}" into the toolbox'.format(
                            filename=TOOLBOX_CONF_FILE, ext=CONF_EXT, section=section, tool=newtool.name))


    def __create_tool(self, section):
        """
        Create a Tool object
        :param section: Tool section into the toolbox settings file
        :return: The created Tool instance
        """
        tool_config = defaultdict(str)

        if not self.__parse_tool_options(section, tool_config): return None
        if not self.__parse_tool_install_status(tool_config):   return None

        return Tool(
            tool_config['name_clean'],
            tool_config['name'],
            tool_config['description'],
            tool_config['target_service'],
            tool_config['installed'],
            tool_config['last_update'],
            tool_config['install'],
            tool_config['update'],
            tool_config['check_command']
        )


    def __parse_tool_options(self, section, tool_config):
        """
        Check and parse options from a given tool section
        :param section: Tool section into the toolbox settings file
        :param tool_config: A defaultdict(str) storing tool config which is updated into this method
        :return: Boolean indicating status
        """
        log_prefix = '[{filename}{ext} | Section "{section}"]'.format(
                        filename=TOOLBOX_CONF_FILE, ext=CONF_EXT, section=section)

        optparsed = self.config_parsers[TOOLBOX_CONF_FILE].options(section)
        for opt in TOOL_OPTIONS[MANDATORY]:
            if opt not in optparsed:
                logger.warning('{prefix} Missing mandatory option "{option}", tool is skipped'.format(
                    prefix=log_prefix, option=opt))
                return False

        tool_config['name_clean'] = section
        for opt in optparsed:
            if opt not in TOOL_OPTIONS[MANDATORY]+TOOL_OPTIONS[OPTIONAL]:
                logger.warning('{prefix} Option "{option}" is not supported, it will be ignored'.format(
                    prefix=log_prefix, option=opt))
                continue

            if opt in TOOL_OPTIONS[MANDATORY]:
                val = self.config_parsers[TOOLBOX_CONF_FILE].safe_get(section, opt, '', None)
                if opt == 'name':
                    tool_config[opt]=StringUtils.clean(val, allowed_specials=['-', '_'])
                elif opt == 'description':
                    tool_config[opt] = val
                elif opt == 'target_service':
                    tool_config[opt] = val.lower()
                    if tool_config[opt] not in self.services.list_services(multi=True):
                        logger.warning('{prefix} Service specified in "target_service" is not supported, ' \
                            'tool is skipped'.format(prefix=log_prefix))
                        return False

                if not tool_config[opt]:
                    logger.warning('{prefix} Mandatory option "{option}" is empty, tool is skipped'.format(
                        prefix=log_prefix, option=opt))
                    return False



            elif opt == 'install':
                tool_config[opt] = Command(cmdtype = CMD_INSTALL, 
                                           cmdline = self.config_parsers[TOOLBOX_CONF_FILE].safe_get(section, opt, '', None))

            elif opt == 'update':
                tool_config[opt] = Command(cmdtype = CMD_UPDATE,
                                           cmdline = self.config_parsers[TOOLBOX_CONF_FILE].safe_get(section, opt, '', None))

            elif opt == 'check_command':
                tool_config[opt] = Command(cmdtype = CMD_CHECK,
                                           cmdline = self.config_parsers[TOOLBOX_CONF_FILE].safe_get(section, opt, '', None))

        return True


    def __parse_tool_install_status(self, tool_config):
        """
        Retrieve install status of a given tool.
        By default: not installed, no last update date
        Must be called after self.__parse_tool_options()
        :param tool_config: A defaultdict(str) storing tool config which is updated into this method
        :return: Boolean
        """
        tool_installed = self.config_parsers[INSTALL_STATUS_CONF_FILE].safe_get(
            tool_config['target_service'], tool_config['name_clean'], 'false', None).lower().strip()

        if   tool_installed == 'false' : tool_config['installed'], tool_config['last_update']  = False , ''
        elif tool_installed == 'true'  : tool_config['installed'], tool_config['last_update']  = True  , ''
        else                           : tool_config['installed'], tool_config['last_update']  = True  , tool_installed

        return True


    def __create_all_services_checks(self):
        """
        Parse each <service_name>.conf file and create a ServiceChecks object for each one.
        A ServiceChecks object stores all checks for a given service.
        :return: None
        """
        for f in self.config_parsers:
            if f in (TOOLBOX_CONF_FILE, INSTALL_STATUS_CONF_FILE):
                continue
            self.__parse_service_checks_config_file(f)


    def __parse_service_checks_config_file(self, service):
        """
        Parse a service checks configuration file <service_name>.conf, in order to:
            - Update service info (default port, protocol, specific options, supported values for
            options of list type) accordingly.
            - Create a ServiceChecks object from parsing of various check sections
        :param service: Service name
        :return: None
        """
        service_config = defaultdict(str)

        categories = self.__parse_section_config(service, service_config)
        self.__parse_section_specific_options(service, service_config)
        self.__parse_section_supported_list_options(service, service_config)

        # Add the service configuration from settings
        self.services.add_service(
            service,
            service_config['default_port'],
            service_config['protocol'],
            service_config['specific_options'],
            service_config['supported_list_options'],
            service_config['auth_types'],
            ServiceChecks(service, categories)
        )

        # Add the various for the service into the ServiceChecks object
        self.__parse_all_checks_sections(service)


    def __parse_section_config(self, service, service_config):
        """
        Parse section [config] in <service_name>.conf, retrieve basic info about service
        (default port/protocol) and retrieve list of categories.
        :param service: Service name
        :param service_config: Dict storing info about service, updated into this method
        :return: List of categories of checks
        :raises SettingsException:
        """
        log_prefix = '[{filename}{ext} | Section "config"]'.format(filename=service, ext=CONF_EXT)

        optparsed = self.config_parsers[service].options('config')
        for opt in SERVICE_CHECKS_CONFIG_OPTIONS[MANDATORY]:
            if opt not in optparsed:
                raise SettingsException('{prefix} Missing mandatory option "{option}", check the file'.format(
                    prefix=log_prefix, option=opt))

        default_port = self.config_parsers[service].safe_get_int('config', 'default_port', None, None)
        protocol     = self.config_parsers[service].safe_get_lower('config', 'protocol', 'tcp', ['tcp', 'udp'])
        categories   = list(map(lambda x: StringUtils.clean(x.lower(), allowed_specials=('-', '_')),
                           self.config_parsers[service].safe_get_list('config', 'categories', ',', [])))
        auth_types   = list(map(lambda x: StringUtils.clean(x.lower(), allowed_specials=('-', '_')),
                           self.config_parsers[service].safe_get_list('config', 'auth_types', ',', []))) \
                       if 'auth_types' in optparsed else None

        if default_port is None or default_port < 0 or default_port > 65535:
            raise SettingsException('{prefix} Invalid value for option "default_port", must be in the range ' \
                '[0-65535]'.format(prefix=log_prefix))

        if not categories:
            raise SettingsException('{prefix} Option "categories" must have at least one category'.format(
                prefix=log_prefix))

        service_config['default_port'] = default_port
        service_config['protocol']     = protocol
        service_config['auth_types']   = auth_types
        return categories


    def __parse_section_specific_options(self, service, service_config):
        """
        Parse section [specific_options] in <service_name>.conf and update service config
        :param service: Service name
        :param service_config: Dict storing info about service, updated into this method
        :return: None
        :raises SettingsException:
        """
        try:
            optparsed = self.config_parsers[service].options('specific_options')
        except configparser.NoSectionError:
            service_config['specific_options'] = dict()
            return 
        specific_options = dict()
        for opt in optparsed:
            option_type = self.config_parsers[service].safe_get_lower('specific_options', opt, None, None)
            if option_type.count(':') == 1:
                option_type, default_value = option_type.split(':')
            opt_clean   = StringUtils.clean(opt.lower(), allowed_specials=('-', '_'))

            if option_type == 'boolean' :  specific_options[opt_clean] = OptionType.BOOLEAN
            elif option_type == 'list'  :  specific_options[opt_clean] = OptionType.LIST
            elif option_type == 'var'   :  specific_options[opt_clean] = OptionType.VAR
            else:
                raise SettingsException('[{filename}{ext} | Section "specific_options"] Specific option named "{option}" has ' \
                    'an invalid type. Supported types are: boolean, list, var'.format(
                        filename = service, ext=CONF_EXT, option=opt))

        service_config['specific_options'] = specific_options


    def __parse_section_supported_list_options(self, service, service_config):
        """
        Parse section [supported_list_options] in <service_name>.conf and retrieve 
        supported values for specific options of type list.
        Must be called after self.__parse_section_config() and self.__parse_section_specific_options()
        :param service: Service name
        :param service_config: Dict storing info about service, updated into this method
        :return: None
        :raises SettingsException:
        """
        options_list = list(filter(lambda x: service_config['specific_options'][x] == OptionType.LIST, 
                                   service_config['specific_options'].keys()))
        if not options_list:
            return dict()
        elif not self.config_parsers[service].has_section('supported_list_options'):
            raise SettingsException('[{filename}{ext}] Missing section [supported_list_options] to store supported ' \
                'values for specific options of type list'.format(filename=service, ext=CONF_EXT))

        log_prefix = '[{filename}{ext} | Section "supported_list_options"]'.format(filename=service, ext=CONF_EXT)
        supported_list_options = dict()
        optparsed = self.config_parsers[service].options('supported_list_options')

        for opt in options_list:
            if 'supported_'+opt not in optparsed:
                raise SettingsException('{prefix} No option "supported_{option}" is defined'.format(
                    prefix=log_prefix, option=opt))

            values = list(map(lambda x: StringUtils.clean(x.lower(), allowed_specials=('-', '_')), 
                         self.config_parsers[service].safe_get_list('supported_list_options', 
                         'supported_'+opt, ',', [])))
            if not values:
                raise SettingsException('{prefix} Option "supported_{option}" is empty'.format(
                    prefix=log_prefix, option=opt))
            supported_list_options[opt] = values

        service_config['supported_list_options'] = supported_list_options


    def __parse_all_checks_sections(self, service):
        """
        Parse all the [check_(.+)] sections of a given service checks settings file
        :param service: Service name
        :return: None
        """
        for section in self.config_parsers[service].sections():
            if section.startswith(PREFIX_SECTION_CHECK):
                check_config = defaultdict(str)
                if not self.__parse_check_section(service, section, check_config): 
                    continue

                newcheck = Check(
                    check_config['name'],
                    check_config['category'],
                    check_config['description'],
                    check_config['tool'],
                    check_config['commands'],
                    check_config['postrun']
                )
                self.services[service]['checks'].add_check(newcheck)


    def __parse_check_section(self, service, section, check_config):
        """
        Check and parse options from a given check section
        :param service: Service name
        :param section: Tool section into the toolbox settings file
        :param check_config: A defaultdict(str) storing check config which is updated into this method
        :return: Boolean indicating status
        """
        log_prefix = '[{filename}{ext} | Section "{section}"]'.format(
                        filename=service, ext=CONF_EXT, section=section)
        optparsed = self.config_parsers[service].options(section)
        for opt in CHECK_OPTIONS[MANDATORY]:
            if opt not in optparsed:
                logger.warning('{prefix} Missing mandatory option "{option}", the check ' \
                    'is ignored'.format(prefix=log_prefix, option=opt))
                return False

        for opt in optparsed:
            if opt not in CHECK_OPTIONS[MANDATORY]+CHECK_OPTIONS[OPTIONAL] and \
               not opt.startswith('command_') and not opt.startswith('context_'):
                logger.warning('{prefix} Option "{option}" is not supported, the check is ' \
                    'ignored'.format(prefix=log_prefix, option=opt))
                continue

            value = self.config_parsers[service].safe_get(section, opt, '', None)
            if opt in CHECK_OPTIONS[MANDATORY]:
                if opt == 'name':
                    check_config[opt] = StringUtils.clean(value, allowed_specials=('_','-'))

                elif opt == 'category':
                    check_config[opt] = StringUtils.clean(value, allowed_specials=('_','-')).lower()
                    if check_config[opt] not in self.services[service]['checks'].categories:
                        logger.warning('{prefix} Category "{category}" is not supported, the check is ' \
                            'ignored'.format(prefix=log_prefix, category=value))
                        return False

                elif opt == 'tool':
                    tool = self.toolbox.get_tool(value)
                    if tool is None:
                        logger.warning('{prefix} The tool "{tool}" does not exist, the check is ' \
                            'ignored'.format(prefix=log_prefix, tool=value))
                        return False
                    check_config[opt] = tool

                else:
                    check_config[opt] = value

                if not check_config[opt]:
                    logger.warning('{prefix} Mandatory option "{option}" is empty, the check is ' \
                        'ignored'.format(prefix=log_prefix, option=opt))
                    return False

            elif opt == 'postrun':
                check_config[opt] = value


        commands = self.__parse_commands(service, section)
        if not commands: return False
        
        check_config['commands'] = commands
        return True   


    def __parse_commands(self, service, section):
        """
        Create Commands object for a given tool.
        Each command is defined in settings file by:
            - command_<command_number> 
            - context_<command_number> (optional)
        :param service: Service name
        :param section: Section name [check_(.+)]
        :return: List of Command instances
        """
        log_prefix = '[{filename}{ext} | Section "{section}"]'.format(
                        filename=service, ext=CONF_EXT, section=section)

        commands = list()
        cmdlines = self.config_parsers[service].safe_get_multi(section, 'command', default=None)
        i = 0
        for cmd in cmdlines:
            context = self.config_parsers[service].safe_get(section, 'context_'+str(i+1), default=None)
            context = self.__parse_context(service, section, i, context)
            if context is None: 
                logger.warning('{prefix} Context is invalid, the check is ignored'.format(prefix=log_prefix))
                return None

            commands.append(Command(cmdtype=CMD_RUN, 
                                    cmdline=cmdlines[i], 
                                    context=context, 
                                    services_config=self.services))
            i += 1
        if not commands:
            logger.warning('{prefix} No command is specified, the check is ignored'.format(prefix=log_prefix))
        return commands


    def __parse_context(self, service, section, num_context, context_str):
        """
        Convert the value of a "context_<command_number>" option into a valid python dict
        :param service: Service name
        :param section: Section name [check_(.+)]
        :param num_context: Number in option name, ie: context_<num_context>
        :param context_str: Context string extracted from settings file
        :return: Context object if parsing is ok, None otherwise
        """
        if not context_str: return Context(None)

        # Retrieve value as dict
        context_str = context_str.replace('NO_AUTH',   str(NO_AUTH))\
                                 .replace('USER_ONLY', str(USER_ONLY))\
                                 .replace('POST_AUTH', str(POST_AUTH))

        log_prefix = '[{filename}{ext} | Section "{section}"] "context_{i}":'.format(
                            filename=service, ext=CONF_EXT, section=section, i=num_context)

        try:
            context = ast.literal_eval(context_str)
        except Exception as e:
            logger.warning('{prefix} Parsing error. Valid dictionary syntax is probably not respected: ' \
                '{ \'key\': \'value\', ... }'.format(prefix=log_prefix))
            return None

        # Check validity of values according to service name
        for opt,val in context.items():
            if opt == 'auth_status':
                if val not in (NO_AUTH, USER_ONLY, POST_AUTH, None):
                    logger.warning('{prefix} Invalid value for "auth_status" context-option. Supported values are: ' \
                        'NO_AUTH, USER_ONLY, POST_AUTH, None'.format(prefix=log_prefix))
                    return None

            elif opt == 'auth_type':
                if service != 'http':
                    logger.warning('{prefix} "auth_type" context-option is only supported for service HTTP'.format(
                        prefix=log_prefix))
                    return None
                elif context[opt] not in self.services[service]['auth_types']:
                    logger.warning('{prefix} "auth_type" context-option does not have a valid value, ' \
                        'check --list-http-auth'.format(prefix=log_prefix))
                    return None

            else:
                if not self.services.is_specific_option_name_supported(opt, service):
                    logger.warning('{prefix} Context-option "{option}" is not supported for service {service}'.format(
                        prefix=log_prefix, option=opt, service=service))
                    return None
                if self.services.get_specific_option_type(opt, service) == OptionType.LIST:
                    if val is not None:
                        if val == 'undefined':
                            context[opt] = ['undefined']
                        else:
                            if isinstance(val, str):
                                val = [val]
                            val = list(map(lambda x: x.lower(), val))
                            for e in val:
                                if e not in self.services[service]['supported_list_options'][opt]:
                                    logger.warning('{prefix} Context-option "{option}" contains an invalid element ' \
                                        '("{element}")'.format(prefix=log_prefix, option=opt, element=e))
                            context[opt] = val
                else:
                    if val is not None and not isinstance(val, bool):
                        logger.warning('{prefix} Context-option "{option}" must have a boolean value (True/False) ' \
                            'or None'.format(prefix=log_prefix, option=opt))   
                        return None   

        return Context(context)


    def change_installed_status(self, target_service, tool_name, install_status):
        """
        Change the install status for a given tool.
        Change is made into the INSTALL_STATUS_CONF_FILE
        If tool installed, put the current datetime

        :param target_service: Name of service targeted by the tool
        :param tool_name: Tool name (Attention: must be the clean name !)
        :param install_status: New install status to set
        :return: Boolean indicating change status
        """
        # 
        value = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if install_status else 'False'

        parser = self.config_parsers[INSTALL_STATUS_CONF_FILE]
        # Create the section [service] if needed
        if target_service not in parser.sections():
            parser.add_section(target_service)

        if not parser.safe_set(target_service, tool_name, value):
            raise SettingsException('Unable to change install status value for the tool {tool}'.format(
                tool=tool_name))

        return self.save(INSTALL_STATUS_CONF_FILE)


    def save(self, conf_filename):
        """
        Save change permanently into the file
        :param conf_filename: Settings filename without extension
        :return: Boolean indicating status
        """
        try:
            config_file = FileUtils.concat_path(SETTINGS_DIR, conf_filename+CONF_EXT)
            with open(config_file, 'w') as handle:
                self.config_parsers[conf_filename].write(handle)
                # Re-read to take change into account
                self.config_parsers[conf_filename].read(config_file, 'utf8') # warning: takes filename as param
            return True
        except:
            logger.error('Error occured when saving changes in settings file named "{filename}"'.format(
                filename=conf_filename))
            traceback.print_exc()
            return False        

