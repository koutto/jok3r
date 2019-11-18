#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Settings 
###
"""

toolbox.conf:
-------------
For each tool registered inside toolbox:
  [tool_name]
  name           = name to display (mandatory)
  description    = short text describing the tool (mandatory)
  target_service = targeted service or "multi" (mandatory)
  virtualenv     = language of the virtual env to use (e.g. python2.7) (optional) 
  install        = installation command-line (optional)
  update         = update command-line (optional)
  check_command  = command to check for correct install (run without args) (optional)


_install_status.conf:
---------------------
For each supported service + "multi":
  [target_service]
  <tool_name>    = False if not installed, datetime of last install/update otherwise


<service_name>.conf (one config file per service):
--------------------------------------------------
[config]
default_port     = [0-65535] (mandatory)
protocol         = tcp|udp (mandatory)
categories       = list of categories for classifying checks ([a-z0-9_-]) (mandatory)
auth_types       = list of authentication types, only for HTTP ([a-z0-9_-]) (optional)

[specific_options] (optional)
<option_name ([a-z0-9_-])> = boolean:default_value|list|var
      (for boolean, default value can be added, True or False. False by default)

[supported_list_options] (required if options of type list are present)
For each option of type "list":
  supported_<option_name> = list of supported values for the option ([a-z0-9_-])

[products] (optional)
  <product_type> ([a-z0-9_-]) = list of supported product names ([a-zA-Z0-9_\/-. ])
  format: [vendor/]product_name (vendor can be omitted if no confusion)
  It is also possible to specify the special value "any" in order to support any product
  name for this type

For each check:
  [check_<check_name>]
  name           = display name (mandatory) 
  category       = category inside which this check is classified (mandatory)
  description    = short text describing the check (mandatory)
  tool           = tool_name of the tool to use (mandatory)
  apikey         = name of required API key to run the check (e.g. "vulners") (optional)
  For each command (there must be at least one command):
      command_<command_number> = command-line for the check, multiple tags supported
      context_<command_number> = context that must be met to run the command (optional)


attack_profiles.conf:
---------------------
[<profile-name>]
description = short text describing the profile (mandatory)
<service_name> = <ordered list of checks to run>

"""
import ast
import re
import traceback
import configparser
from datetime import datetime
from collections import defaultdict

from lib.core.AttackProfiles import AttackProfile, AttackProfiles
from lib.core.Check import Check
from lib.core.Command import Command
from lib.core.Config import *
from lib.core.Constants import *
from lib.core.ContextRequirements import ContextRequirements
from lib.core.Exceptions import SettingsException
from lib.core.ServiceChecks import ServiceChecks
from lib.core.ServicesConfig import ServicesConfig
from lib.core.Tool import Tool
from lib.core.Toolbox import Toolbox
from lib.output.Logger import logger
from lib.utils.DefaultConfigParser import DefaultConfigParser
from lib.utils.FileUtils import FileUtils
from lib.utils.StringUtils import StringUtils
from apikeys import API_KEYS


class Settings:
    """
    Class used to parse all settings files:
        - toolbox.conf         : File storing configurations about all tools
        - <service_name>.conf  : Each supported service has a corresponding .conf file
        - _install_status.conf : Install status for each tool & last update if installed
        - attack_profiles.conf : Attack profiles

    Settings class is instanciated when starting Jok3r.
    """

    def __init__(self):
        """
        Start the parsing of settings files and create the Settings object.

        :raises SettingsException: Exception raised if any error is encountered while 
            parsing files (syntax error, missing mandatory file...)
        """
        self.config_parsers = dict() # Dict of DefaultConfigParser indexed by filename
        self.toolbox = None # Receives Toolbox object
        self.services = None # Receives ServicesConfig object
        self.attack_profiles = None # Receives AttackProfiles object

        # Check directory
        if not FileUtils.is_dir(SETTINGS_DIR):
            raise SettingsException('Configuration directory ({dir}) does not ' \
                'exist'.format(dir=SETTINGS_DIR))

        # Check presence of *.conf files
        files = FileUtils.list_directory(SETTINGS_DIR)
        for f in files:
            if not FileUtils.check_extension(f, CONF_EXT):
                files.remove(f)

        if not files:
            raise SettingsException('Configuration directory ({dir}) does not ' \
                'store any *.conf file'.format(dir=SETTINGS_DIR))

        if TOOLBOX_CONF_FILE+CONF_EXT not in files:
            raise SettingsException('Missing mandatory {toolbox}{ext} settings ' \
                'file in directory "{dir}"'.format(
                    toolbox=TOOLBOX_CONF_FILE, 
                    ext=CONF_EXT, 
                    dir=SETTINGS_DIR))

        if ATTACK_PROFILES_CONF_FILE+CONF_EXT not in files:
            raise SettingsException('Missing mandatory {profiles}{ext} settings ' \
                'file in directory "{dir}"'.format(
                    profiles=ATTACK_PROFILES_CONF_FILE,
                    ext=CONF_EXT,
                    dir=SETTINGS_DIR))

        # Create _install_status.conf file if necessary
        if INSTALL_STATUS_CONF_FILE+CONF_EXT not in files:
            open(SETTINGS_DIR+'/'+INSTALL_STATUS_CONF_FILE+CONF_EXT, 'a').close()
            logger.info('{status}{ext} settings file created in directory ' \
                '"{dir}"'.format(status=INSTALL_STATUS_CONF_FILE, 
                                 ext=CONF_EXT, 
                                 dir=SETTINGS_DIR))
            files.append(INSTALL_STATUS_CONF_FILE+CONF_EXT)

        # Parse configuration files and create objects from them
        self.__parse_all_conf_files(files)
        self.__create_toolbox()
        self.__create_all_services_config_and_checks()
        self.__create_attack_profiles()
    

    #------------------------------------------------------------------------------------
    # Config files reading

    def __parse_all_conf_files(self, files):
        """
        Parse all configuration files into the settings directory.
        Initialize ServicesConfig object with list of supported services.

        :param list files: List of files in settings directory
        """
        services = list()
        for f in files:
            name = FileUtils.remove_ext(f).lower().strip()
            if name not in (INSTALL_STATUS_CONF_FILE, 
                            TOOLBOX_CONF_FILE,
                            ATTACK_PROFILES_CONF_FILE):
                services.append(name)

            full_path = FileUtils.concat_path(SETTINGS_DIR, f)
            self.config_parsers[name] = DefaultConfigParser()
            # Utf8 to avoid encoding issues
            self.config_parsers[name].read(full_path, 'utf8') 

        services.append('multi') # Add support for special "multi" service
        self.services = ServicesConfig(services)


    #------------------------------------------------------------------------------------
    # Toolbox config file parsing

    def __create_toolbox(self):
        """Create the toolbox and update self.toolbox."""
        self.toolbox = Toolbox(self, self.services.list_services(multi=True))

        for section in self.config_parsers[TOOLBOX_CONF_FILE].sections():
            newtool = self.__create_tool(section)
            if newtool is not None:
                if not self.toolbox.add_tool(newtool):
                    logger.warning('[{filename}{ext} | Section "{section}"] Unable ' \
                        'to add tool "{tool}" into the toolbox'.format(
                            filename=TOOLBOX_CONF_FILE, 
                            ext=CONF_EXT, 
                            section=section, 
                            tool=newtool.name))


    def __create_tool(self, section):
        """
        Create a Tool object.

        :param str section: Section name corresponding to the tool in toolbox.conf
        :return: The newly created tool
        :rtype: Tool
        """
        tool_config = defaultdict(str)

        if not self.__parse_tool_options(section, tool_config): 
            return None
        if not self.__parse_tool_install_status(tool_config):
            return None

        return Tool(
            tool_config['name'],
            tool_config['description'],
            tool_config['target_service'],
            tool_config['installed'],
            tool_config['last_update'],
            tool_config['virtualenv'],
            tool_config['install'],
            tool_config['update'],
            tool_config['check_command']
        )


    def __parse_tool_options(self, section, tool_config):
        """
        Check and parse options from a given tool section.

        :param str section: Section name corresponding to the tool in toolbox.conf
        :param defaultdict(str) tool_config: Tool configuration updated in this method
        :return: Status of parsing
        :rtype: bool
        """
        log_prefix = '[{filename}{ext} | Section "{section}"]'.format(
                        filename=TOOLBOX_CONF_FILE, ext=CONF_EXT, section=section)

        # Check presence of mandatory options
        optparsed = self.config_parsers[TOOLBOX_CONF_FILE].options(section)
        for opt in TOOL_OPTIONS[MANDATORY]:
            if opt not in optparsed:
                logger.warning('{prefix} Missing mandatory option "{option}", ' \
                    'tool is skipped'.format(prefix=log_prefix, option=opt))
                return False

        # Loop over options
        for opt in optparsed:

            # Check for unsupported options
            if opt not in TOOL_OPTIONS[MANDATORY]+TOOL_OPTIONS[OPTIONAL]:
                logger.warning('{prefix} Option "{option}" is not supported, ' \
                    'it will be ignored'.format(prefix=log_prefix, option=opt))
                continue

            # Add value
            val = self.config_parsers[TOOLBOX_CONF_FILE].safe_get(
                section, opt, '', None)

            if opt == 'name':
                tool_config[opt] = StringUtils.clean(val, allowed_specials=['-', '_'])

            elif opt == 'description':
                tool_config[opt] = val

            elif opt == 'target_service':
                tool_config[opt] = val.lower()

                if tool_config[opt] not in self.services.list_services(multi=True):
                    logger.warning('{prefix} Service specified in "target_service" is ' \
                        'not supported, tool is skipped'.format(prefix=log_prefix))
                    return False

            elif opt == 'virtualenv':
                tool_config[opt] = val.lower()

                # For Python, format must be "python<version>"
                if tool_config[opt].startswith('python'):
                    m = re.match('python(?P<version>[0-9](\.[0-9])*)', tool_config[opt])
                    if not m:
                        logger.warning('{prefix} Invalid Python virtualenv, must be: ' \
                            'virtualenv = python<version>. Tool is skipped'.format(
                                prefix=log_prefix))
                        return False                                

                # For Ruby, make sure to have a format like "ruby-<version>"
                # Format "ruby<version>" is accepted and turned into "ruby-<version>"
                if tool_config[opt].startswith('ruby'):
                    m1 = re.match('ruby(?P<version>[0-9](\.[0-9])*)', tool_config[opt])
                    m2 = re.match('ruby-(?P<version>[0-9](\.[0-9])*)', tool_config[opt])
                    if m1:
                        tool_config[opt] = 'ruby-{version}'.format(
                            version=m.group('version'))
                    elif not m2:
                        logger.warning('{prefix} Invalid Ruby virtualenv, must be: ' \
                            'virtualenv = ruby-<version>. Tool is skipped'.format(
                                prefix=log_prefix))
                        return False
                        

            elif opt == 'install':
                tool_config[opt] = Command(cmdtype=CmdType.INSTALL, cmdline=val)

            elif opt == 'update':
                tool_config[opt] = Command(cmdtype=CmdType.UPDATE, cmdline=val)

            elif opt == 'check_command':
                tool_config[opt] = Command(cmdtype=CmdType.CHECK, cmdline=val)

            # Check for empty mandatory option
            if opt in TOOL_OPTIONS[MANDATORY] and not tool_config[opt]:
                logger.warning('{prefix} Mandatory option "{option}" is empty, tool ' \
                    'is skipped'.format(prefix=log_prefix, option=opt))
                return False                

        return True


    def __parse_tool_install_status(self, tool_config):
        """
        Retrieve install status of a given tool and update tool configuration 
        accordingly.
        By default: not installed, no last update date
        Must be called after self.__parse_tool_options()

        :param defaultdict(str) tool_config: Tool configuration updated in this method
        :return: Status of parsing 
        :rtype: bool
        """
        is_installed = self.config_parsers[INSTALL_STATUS_CONF_FILE].safe_get(
            tool_config['target_service'], 
            tool_config['name'], 
            'false', None).lower().strip()

        if is_installed == 'false': 
            tool_config['installed'], tool_config['last_update']  = False, ''

        elif is_installed == 'true': 
            tool_config['installed'], tool_config['last_update']  = True, ''

        else: 
            tool_config['installed'], tool_config['last_update']  = True, is_installed

        return True


    #------------------------------------------------------------------------------------
    # Services configurations and checks parsing

    def __create_all_services_config_and_checks(self):
        """Parse each <service_name>.conf file"""
        for f in self.config_parsers:
            if f in (INSTALL_STATUS_CONF_FILE, 
                     TOOLBOX_CONF_FILE,
                     ATTACK_PROFILES_CONF_FILE):
                continue

            self.__parse_service_checks_config_file(f)


    def __parse_service_checks_config_file(self, service):
        """
        Parse a service checks configuration file <service_name>.conf, in order to
        create a ServiceChecks object and to update ServicesConfig object with 
        service information (default port, protocol, supported specific options,
        supported products, authentication type for HTTP).

        :param str service: Service name
        """
        service_config = defaultdict(str)

        categories = self.__parse_section_config(service, service_config)
        self.__parse_section_specific_options(service, service_config)
        self.__parse_section_supported_list_options(service, service_config)
        self.__parse_section_products(service, service_config)

        # Add the service configuration from settings
        self.services.add_service(
            service,
            service_config['default_port'],
            service_config['protocol'],
            service_config['specific_options'],
            service_config['supported_list_options'],
            service_config['products'],
            service_config['auth_types'],
            ServiceChecks(service, categories)
        )

        # Add the various checks for the service into the ServiceChecks object
        self.__parse_all_checks_sections(service)


    #------------------------------------------------------------------------------------
    # Services configurations parsing

    def __parse_section_config(self, service, service_config):
        """
        Parse section [config] in <service_name>.conf, retrieve basic info about service
        (default port/protocol) and retrieve list of supported categories of checks for
        this service.

        :param str service: Service name
        :param defaultdict(str) service_config: Information about the service, updated 
            into this method
        :return: List of categories of checks
        :rtype: list(str)
        :raises SettingsException: Exception raised if any unrecoverable error is 
            encountered while parsing the section
        """
        log_prefix = '[{filename}{ext} | Section "config"]'.format(
            filename=service, ext=CONF_EXT)

        # Check presence of mandatory options in [config]
        optparsed = self.config_parsers[service].options('config')
        for opt in SERVICE_CHECKS_CONFIG_OPTIONS[MANDATORY]:
            if opt not in optparsed:
                raise SettingsException('{prefix} Missing mandatory option "{option}"' \
                    ', check the file'.format(prefix=log_prefix, option=opt))

        # Get port number
        default_port = self.config_parsers[service].safe_get_int(
            'config', 'default_port', None, None)

        if default_port is None or default_port < 0 or default_port > 65535:
            raise SettingsException('{prefix} Invalid value for option "default_port",' \
                ' must be in the range [0-65535]'.format(prefix=log_prefix))

        # Get protocol
        protocol = self.config_parsers[service].safe_get_lower(
            'config', 'protocol', 'tcp', ['tcp', 'udp'])

        # Get categories of checks as a list, clean each element
        categories = list(map(lambda x: StringUtils.clean(
            x.lower(), allowed_specials=('-', '_')), 
            self.config_parsers[service].safe_get_list('config', 'categories', ',', [])))

        if not categories:
            raise SettingsException('{prefix} Option "categories" must have at least '\
                'one category'.format(prefix=log_prefix))

        # Get authentication type (for HTTP) as a list, clean each element
        if 'auth_types' in optparsed:
            auth_types = list(map(lambda x: StringUtils.clean(
                x.lower(), allowed_specials=('-', '_')),
                self.config_parsers[service].safe_get_list(
                    'config', 'auth_types', ',', [])))
        else:
            auth_types = None

        # Update service configuration with parsed information
        service_config['default_port'] = default_port
        service_config['protocol']     = protocol
        service_config['auth_types']   = auth_types

        return categories


    def __parse_section_specific_options(self, service, service_config):
        """
        Parse section [specific_options] in <service_name>.conf and update service 
        configuration with supported specific options for the service and their
        respective types.

        :param str service: Service name
        :param defaultdict(str) service_config: Information about the service, updated 
            into this method
        :return: None
        :raises SettingsException: Exception raised if any unrecoverable error is 
            encountered while parsing the section
        """

        # Case when no [specific_options] can be found
        try:
            optparsed = self.config_parsers[service].options('specific_options')
        except configparser.NoSectionError:
            service_config['specific_options'] = dict()
            return 

        specific_options = dict()

        # Loop over supported specific options
        for opt in optparsed:
            # Get option type
            option_type = self.config_parsers[service].safe_get_lower(
                'specific_options', opt, None, None)

            # Handle case when default value is specified (for boolean)
            if option_type.count(':') == 1:
                option_type, default_value = option_type.split(':')

            opt_clean   = StringUtils.clean(opt.lower(), allowed_specials=('-', '_'))

            if option_type == 'boolean': 
                specific_options[opt_clean] = OptionType.BOOLEAN

            elif option_type == 'list': 
                specific_options[opt_clean] = OptionType.LIST

            elif option_type == 'var': 
                specific_options[opt_clean] = OptionType.VAR

            else:
                raise SettingsException('[{filename}{ext} | Section ' \
                    '"specific_options"]  Specific option named "{option}" has ' \
                    'an invalid type. Supported types are: boolean, list, var'.format(
                        filename = service, ext=CONF_EXT, option=opt))

        # Update service configuration with specific options names and types
        service_config['specific_options'] = specific_options


    def __parse_section_supported_list_options(self, service, service_config):
        """
        Parse section [supported_list_options] in <service_name>.conf and update service 
        configuration with supported values for specific options of type list.
        Must be called after self.__parse_section_config() and 
        self.__parse_section_specific_options().

        :param defaultdict(str) service_config: Information about the service, updated 
            into this method
        :return: None
        :raises SettingsException: Exception raised if any unrecoverable error is 
            encountered while parsing the section
        """

        # Get names of specific options of type list
        options_list = list(filter(
            lambda x: service_config['specific_options'][x] == OptionType.LIST, 
            service_config['specific_options'].keys()))

        if not options_list:
            return
        elif not self.config_parsers[service].has_section('supported_list_options'):
            raise SettingsException('[{filename}{ext}] Missing section ' \
                '[supported_list_options] to store supported values for specific ' \
                'options of type "list"'.format(filename=service, ext=CONF_EXT))

        log_prefix = '[{filename}{ext} | Section "supported_list_options"]'.format(
            filename=service, ext=CONF_EXT)

        supported_list_options = dict()
        optparsed = self.config_parsers[service].options('supported_list_options')

        # Loop over specific options of type list
        for opt in options_list:

            # If missing option
            if 'supported_'+opt not in optparsed:
                raise SettingsException('{prefix} No option "supported_{option}" ' \
                    'is defined'.format(prefix=log_prefix, option=opt))

            # Values are put in lowercase, no spaces, no special chars (except -, _)
            values = list(map(lambda x: StringUtils.clean(
                x.lower(), allowed_specials=('-', '_')), 
                self.config_parsers[service].safe_get_list(
                    'supported_list_options', 'supported_'+opt, ',', [])))

            if not values:
                raise SettingsException('{prefix} Option "supported_{option}" is ' \
                    'empty'.format(prefix=log_prefix, option=opt))

            supported_list_options[opt] = values

        # Update service configuration with lists of supported values
        service_config['supported_list_options'] = supported_list_options


    def __parse_section_products(self, service, service_config):
        """
        Parse section [products] in <service_name>.conf and retrieve supported values 
        for each product type.

        :param str service: Service name
        :param dict service_config: Service configuration, updated into this method
        :return: None
        :raises SettingsException: Exception raised if unconsistent values detected
        """

        # First, check if config file has a [products] section
        if not self.config_parsers[service].has_section('products'):
            service_config['products'] = dict()
            return

        log_prefix = '[{filename}{ext} | Section "products"]'.format(
            filename=service, ext=CONF_EXT)

        products = dict()
        optparsed = self.config_parsers[service].options('products')

        # Loop over product types in [products]
        for product_type in optparsed:

            # Clean the product type
            product_type = StringUtils.clean(product_type.lower(), 
                allowed_specials=('-', '_'))
            
            # Get supported product names as a list.
            # Only some special chars allowed, spaces allowed
            # '/' is used to separate vendor name (optional) and product name
            product_names = self.config_parsers[service].safe_get_list(
                'products', product_type, ',', [])
            product_names = list(map(lambda x: StringUtils.clean(
                x, allowed_specials=('-', '_', '.', '/', '\\', ' ')), product_names))

            if not product_names:
                raise SettingsException('{prefix} Option "{option}" is empty'.format(
                    prefix=log_prefix, option=opt))

            products[product_type] = product_names        

        # Update service configuration with supported products
        service_config['products'] = products
        return


    #------------------------------------------------------------------------------------
    # Services security checks parsing

    def __parse_all_checks_sections(self, service):
        """
        Parse all the [check_(.+)] sections of a given service checks settings file
        <service_name>.conf.

        :param str service: Service name
        """
        for section in self.config_parsers[service].sections():

            # Check section begins with "check_"
            if section.startswith(PREFIX_SECTION_CHECK):
                check_config = defaultdict(str)

                # Parse section
                if not self.__parse_check_section(service, section, check_config): 
                    continue

                # Create new Check object and add it to services configuration
                newcheck = Check(
                    check_config['name'],
                    check_config['category'],
                    check_config['description'],
                    check_config['tool'],
                    check_config['commands'],
                    required_apikey=check_config['apikey']
                )
                self.services[service]['checks'].add_check(newcheck)


    def __parse_check_section(self, service, section, check_config):
        """
        Check and parse options from a given check section.

        :param str service: Service name
        :param str section: Section corresponding to the check to parse
        :param defaultdict(str) check_config: Check configuration, updated into this
            method
        :return: Status of parsing
        :rtype: bool
        """
        log_prefix = '[{filename}{ext} | Section "{section}"]'.format(
                        filename=service, ext=CONF_EXT, section=section)

        # Check presence of mandatory options in [check_<name>] section
        optparsed = self.config_parsers[service].options(section)
        for opt in CHECK_OPTIONS[MANDATORY]:
            if opt not in optparsed:
                logger.warning('{prefix} Missing mandatory option "{option}", the ' \
                    ' check is ignored'.format(prefix=log_prefix, option=opt))
                return False

        # Loop over options
        for opt in optparsed:

            # Check for unsupported options
            if opt not in CHECK_OPTIONS[MANDATORY]+CHECK_OPTIONS[OPTIONAL] \
               and not opt.startswith('command_') and not opt.startswith('context_'):
                logger.warning('{prefix} Option "{option}" is not supported, the ' \
                    'check is ignored'.format(prefix=log_prefix, option=opt))
                continue

            # Add value
            val = self.config_parsers[service].safe_get(section, opt, '', None)

            if opt == 'name':
                check_config[opt] = StringUtils.clean(val, allowed_specials=('_','-'))

            elif opt == 'category':
                cat = StringUtils.clean(val, allowed_specials=('_','-'))
                check_config[opt] = cat.lower()

                if check_config[opt] not in self.services[service]['checks'].categories:
                    logger.warning('{prefix} Category "{category}" is not supported, ' \
                        'the check is ignored'.format(prefix=log_prefix, category=val))
                    return False      

            elif opt == 'tool':
                tool = self.toolbox.get_tool(val)
                if tool is None:
                    logger.warning('{prefix} The tool "{tool}" does not exist, the ' \
                        'check is ignored'.format(prefix=log_prefix, tool=val))
                    return False
                check_config[opt] = tool

            elif opt == 'apikey':
                if val not in API_KEYS.keys():
                    logger.warning('{prefix} API key "{apikey}" is not supported in ' \
                        'apikeys.py. Check is ignored'.format(
                            prefix=log_prefix, apikey=val))
                    return False
                check_config[opt] = val

            else:
                check_config[opt] = val   

            # Check for empty mandatory option
            if opt in CHECK_OPTIONS[MANDATORY] and not check_config[opt]:
                logger.warning('{prefix} Mandatory option "{option}" is empty, the ' \
                    'check is ignored'.format(prefix=log_prefix, option=opt))
                return False

        # Parse commands along with optional context requirements
        commands = self.__parse_commands(service, section)
        if not commands: 
            return False
        
        check_config['commands'] = commands
        return True   


    def __parse_commands(self, service, section):
        """
        Parse commands for a given tool and create Commands object. 
        Each command is defined in configuration file by:
            - command_<command_number> 
            - context_<command_number> (optional)

        :param str service: Service name
        :param str section: Section name of the check
        :return: Created Command objects
        :rtype: list(Command)
        """
        log_prefix = '[{filename}{ext} | Section "{section}"]'.format(
                        filename=service, ext=CONF_EXT, section=section)

        commands = list()

        # Get command lines
        cmdlines = self.config_parsers[service].safe_get_multi(
            section, 'command', default=None)

        i = 0
        # Loop over command lines
        for cmd in cmdlines:

            # Parse context requirements and create ContextRequirements object
            context = self.config_parsers[service].safe_get(
                section, 'context_'+str(i+1), default=None)

            context_requirements = self.__parse_context_requirements(
                service, section, i+1, context)

            if context_requirements is None: 
                logger.warning('{prefix} Context requirements are invalid, the check ' \
                    'is ignored'.format(prefix=log_prefix))
                return None

            # Create the Command object
            command = Command(cmdtype=CmdType.RUN, 
                              cmdline=cmdlines[i], 
                              context_requirements=context_requirements, 
                              services_config=self.services)
            commands.append(command)
            i += 1

        if not commands:
            logger.warning('{prefix} No command is specified, the check is ' \
                'ignored'.format(prefix=log_prefix))

        return commands


    def __parse_context_requirements(self, service, section, num_context, context_str):
        """
        Convert the value of a "context_<command_number>" option into a valid 
        Python dictionary, and initialize a fresh ContextRequirements object from it.

        :param str service: Service name
        :param str section: Section name [check_<name>]
        :param int num_context: Number in option name, ie: context_<num_context>
        :param str context_str: Context string extracted from settings file

        :return: Context if parsing is ok, None otherwise
        :rtype: Context|None
        """

        # When no context is defined in settings, it means there is no requirement
        if not context_str: 
            return ContextRequirements(specific_options=None, 
                                       products=None, 
                                       osfamily=None, 
                                       auth_status=None,
                                       raw='<empty>')

        log_prefix = '[{filename}{ext} | Section "{section}"] "context_{i}":'.format(
            filename=service, ext=CONF_EXT, section=section, i=num_context)

        # Keep raw context string for debugging
        context_str_raw = context_str

        # Retrieve value as dict
        # Note: Make sure to replace special constants
        context_str = context_str.replace('NO_AUTH',   str(NO_AUTH))\
                                 .replace('USER_ONLY', str(USER_ONLY))\
                                 .replace('POST_AUTH', str(POST_AUTH))
        try:
            context = ast.literal_eval(context_str)
        except Exception as e:
            logger.warning('{prefix} Parsing error. Valid dictionary syntax is ' \
                'probably not respected: { \'key\': \'value\', ... }'.format(
                    prefix=log_prefix))
            return None

        # Check validity of context requirements
        req_specific_options = dict()
        req_products = dict()
        for cond,val in context.items():

            # Auth status
            if cond == 'auth_status':
                if val not in (NO_AUTH, USER_ONLY, POST_AUTH, None):
                    logger.warning('{prefix} Invalid value for "auth_status" ' \
                        'context requirement. Supported values are: NO_AUTH, ' \
                        'USER_ONLY, POST_AUTH, None'.format(prefix=log_prefix))
                    return None

            # Auth type (for HTTP)
            elif cond == 'auth_type':
                if service != 'http':
                    logger.warning('{prefix} "auth_type" context requirement is only ' \
                        'supported for service HTTP'.format(prefix=log_prefix))
                    return None
                elif context[cond] not in self.services[service]['auth_types']:
                    logger.warning('{prefix} "auth_type" context requirement does not ' \
                        'have a valid value, check info --list-http-auth'.format(
                            prefix=log_prefix))
                    return None

            # OS
            elif cond == 'os':
                if not val:
                    logger.warning('{prefix} "os" context requirement is specified' \
                        'but no value is provided'.format(prefix=log_prefix))
                    return None

            # Specific option
            elif self.services.is_specific_option_name_supported(cond, service):
                if val is None:
                    continue

                type_ = self.services.get_specific_option_type(cond, service)

                # For specific option of type "list"
                # Value can be either of type: None, str, list
                # Possible values:
                # - None: no restriction on the specific option value (default),
                # - str: restriction on a given value,
                # - list: restriction on several possible values
                # - 'undefined': specific option must not be defined
                if type_ == OptionType.LIST:
                    if val == 'undefined':
                        req_specific_options[cond] = ['undefined']
                    else:
                        if isinstance(val, str):
                            val = [val]
                        val = list(map(lambda x: x.lower(), val))
                        sup_vals = self.services[service]['supported_list_options'][cond]
                        for e in val:
                            if e not in sup_vals:
                                logger.warning('{prefix} Context requirement ' \
                                    '"{option}" contains an invalid element ' \
                                    '("{element}")'.format(prefix=log_prefix, 
                                        option=cond, element=e))
                                return None
                        req_specific_options[cond] = val

                # For specific option of type "boolean" or "var"
                # Context requirement must be boolean or None             
                elif type_ in (OptionType.BOOLEAN, OptionType.VAR):
                    if not isinstance(val, bool):
                        logger.warning('{prefix} Context requirement "{option}" must ' \
                            'have a boolean value (True/False) or None'.format(
                                prefix=log_prefix, option=cond))   
                        return None 

                    req_specific_options[cond] = val

            # Product
            elif self.services.is_product_type_supported(cond, service):

                # Possible values:
                # - None: no restriction on the product name (default),
                # - str: restriction on a given product name,
                # - list: restriction on several possible product names,
                # - 'undefined': product must not be defined
                # - 'any': product must be defined (any value)
                # - 'any|version_known': product+version must be defined
                #
                # In context requirements, product name can also embed requirement on 
                # product version by appending "|version_requirements" to product name
                if val in ('undefined', 'any', 'any|version_known'):
                    req_products[cond] = [val]
                else:
                    if isinstance(val, str):
                        val = [val]
                    list_supported_product_names = list(map(lambda x: x.lower(), 
                        self.services[service]['products'][cond]))

                    for e in val:
                        # Check if [vendor/]product_name is in the list of supported 
                        # product names (ignore version requirements if present) if such
                        # list has been provided. Otherwise, if "any" has been provided
                        # no need to perform any check on product name here.
                        if 'any' in list_supported_product_names:
                            req_products[cond] = val 
                        else:
                            product_name = e[:e.index('|')] if '|' in e else e
                            # Handle the case where inversion is used with prefix "!"
                            if len(product_name) > 0 and product_name[0] == '!':
                                product_name = product_name[1:]
                            if product_name.lower() not in list_supported_product_names:
                                logger.warning('{prefix} Context requirement "{option}" '\
                                    'contains an invalid product ("{product}")'.format(
                                        prefix=log_prefix, 
                                        option=cond, 
                                        product=product_name))
                            else:
                                req_products[cond] = val                

            # Not supported
            else:
                logger.warning('{prefix} Context requirement "{option}" is not ' \
                    'supported for service {service}'.format(
                        prefix=log_prefix, option=cond, service=service))
                return None

        return ContextRequirements(specific_options=req_specific_options,
                                   products=req_products,
                                   osfamily=context.get('os'),
                                   auth_status=context.get('auth_status'),
                                   auth_type=context.get('auth_type'),
                                   raw=context_str_raw)


    #------------------------------------------------------------------------------------
    # Attack profiles parsing

    def __create_attack_profiles(self):
        """Create Attack Profiles and update self.attack_profiles."""

        self.attack_profiles = AttackProfiles()

        for section in self.config_parsers[ATTACK_PROFILES_CONF_FILE].sections():
            newprofile = self.__create_attack_profile(section)
            if newprofile is not None:
                if not self.attack_profiles.add(newprofile):
                    logger.warning('[{filename}{ext} | Section "{section}"] Unable ' \
                        'to add attack profile "{profile}" (duplicate)'.format(
                            filename=ATTACK_PROFILES_CONF_FILE, 
                            ext=CONF_EXT, 
                            section=section, 
                            profile=newprofile.name))


    def __create_attack_profile(self, section):
        """
        Create an AttackProfile object.

        :param str section: Section name corresponding to the profile in 
            attack_profiles.conf
        :return: The newly created Attack Profile, or None in case of problem
        :rtype: AttackProfile|None
        """
        log_prefix = '[{filename}{ext} | Section "{section}"]'.format(
            filename=ATTACK_PROFILES_CONF_FILE, ext=CONF_EXT, section=section)

        description = ''
        checks = defaultdict(list)

        optparsed = self.config_parsers[ATTACK_PROFILES_CONF_FILE].options(section)

        # Loop over options
        for opt in optparsed:

            # Description of attack profile
            if opt == 'description':
                description = self.config_parsers[ATTACK_PROFILES_CONF_FILE].safe_get(
                    section, opt, '', None)

            # List of checks (ordered) for a service (name of the option must 
            # correspond to the name of the service)
            elif self.services.is_service_supported(opt, multi=False):
                list_checks = self.config_parsers[ATTACK_PROFILES_CONF_FILE]\
                    .safe_get_list(section, opt, ',', [])

                if not list_checks:
                    logger.warning('{prefix} List of checks for {service} is empty, ' \
                        'the attack profile is skipped'.format(
                            prefix=log_prefix, service=opt))
                    return None

                # Check existence of checks
                for c in list_checks:
                    if not self.services.get_service_checks(opt).is_existing_check(c):
                        logger.warning('{prefix} The check "{check}" does not exist ' \
                            'for service {service}, the attack profile is ' \
                            'skipped'.format(prefix=log_prefix, check=c, service=opt))
                        return None

                # Add list of checks in dictionnary for the corresponding service
                checks[opt] = list_checks

            # Unsupported option
            else:
                logger.warning('{prefix} The option "{option}" is not supported ' \
                    'for attack profile configuration'.format(
                        prefix=log_prefix, option=opt))
                return None

        if not description:
            logger.warning('{prefix} A description must be given for the attack ' \
                'profile'.format(prefix=log_prefix))
            return None

        return AttackProfile(section, description, checks)


    #------------------------------------------------------------------------------------
    # Install status configuration modification

    def change_installed_status(self, target_service, tool_name, install_status):
        """
        Change the install status for a given tool.
        Change is made into the INSTALL_STATUS_CONF_FILE
        If tool installed, put the current datetime.

        :param str target_service: Name of service targeted by the tool
        :param str tool_name: Name of the tool
        :param bool install_status: New install status to set
        :return: Status of change
        :rtype: bool
        """
        if install_status: 
            value = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        else:
            value = 'False'

        parser = self.config_parsers[INSTALL_STATUS_CONF_FILE]

        # Create the section [service] if needed
        if target_service not in parser.sections():
            parser.add_section(target_service)

        # Add/Update the install status
        if not parser.safe_set(target_service, tool_name, value):
            raise SettingsException('Unable to change install status value for the ' \
                'tool {tool}'.format(tool=tool_name))

        # Save change permanently into the file
        return self.save(INSTALL_STATUS_CONF_FILE)


    def save(self, conf_filename):
        """
        Save change permanently into the file.

        :param str conf_filename: Settings filename without extension
        :return: Status of saving
        :rtype: bool
        """
        try:
            config_file = FileUtils.concat_path(SETTINGS_DIR, conf_filename+CONF_EXT)
            with open(config_file, 'w') as handle:
                self.config_parsers[conf_filename].write(handle)
                # Re-read to take change into account
                # Warning: read() takes filename as param 
                self.config_parsers[conf_filename].read(config_file, 'utf8') 
            return True
        except:
            logger.error('Error occured when saving changes in settings file ' \
                'named "{filename}"'.format(filename=conf_filename))
            traceback.print_exc()
            return False        

