# -*- coding: utf-8 -*-
###
### Core > ServicesConfig
###
from collections import defaultdict

from lib.core.Constants import *
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.utils.OrderedDefaultDict import OrderedDefaultDict
from lib.utils.StringUtils import StringUtils


class ServicesConfig:
    """
    Map each supported service to their settings and to their ServiceChecks object
    """

    def __init__(self, list_services):
        """
        Initialize ServicesConfig with a list of service names
        :param list_services: List of service names
        """
        self.services = OrderedDefaultDict(list, {k:{
                            'default_port'           : None,
                            'protocol'               : None,
                            'specific_options'       : dict(), # Dictionary { specific option : type }
                            'supported_list_options' : dict(), # Dictionary { specific option : list of possible values }
                            'auth_types'             : None,
                            'checks'                 : None, 
                        } for k in list_services})

        #self.services['multi'] = None


    def __getitem__(self, key):
        return self.services[key]

    def __setitem__(self, key, value):
        self.services[key] = value

    def __delitem__(self, key):
        del self.services[key]

    def __contains__(self, key):
        return key in self.services

    def __len__(self):
        return len(self.services)

    def __repr__(self):
        return repr(self.services)

    def keys(self):
        return self.services.keys()

    def values(self):
        return self.services.values()


    def add_service(self, 
                    name, 
                    default_port, 
                    protocol, 
                    specific_options, 
                    supported_list_options,
                    auth_types,
                    service_checks):
        """
        Add a service configuration
        :param name: Service name
        :param default_port: Default port number
        :param protocol: Protocol tcp or udp
        :param specific_options: Dictionary { specific option : type }
        :param supported_list_options: Dictionary { specific option : list of possible values }
        :param auth_types: List of supported authentication types, relevant for HTTP only
        :param service_checks: ServiceChecks object
        """
        service = name.lower()
        self.services[service]['default_port']           = int(default_port)
        self.services[service]['protocol']               = protocol
        self.services[service]['specific_options']       = specific_options
        self.services[service]['supported_list_options'] = supported_list_options
        self.services[service]['auth_types']             = auth_types
        self.services[service]['checks']                 = service_checks


    def list_services(self, multi=False):
        """
        :return: List of service names
        """
        if multi:
            return sorted(list(self.services.keys()))
        else:
            l = list(self.services.keys())
            l.remove('multi')
            return sorted(l)


    def list_all_categories(self):
        """
        :return: Set of all categories of checks (for all services)
        """
        categories = set()
        for svc in self.list_services():
            categories.update(self.services[svc]['checks'].categories)
        return categories


    def get_default_port(self, service):
        if not self.is_service_supported(service, multi=False):
            return None
        return self.services[service]['default_port']


    def get_protocol(self, service):
        if not self.is_service_supported(service, multi=False):
            return None
        return self.services[service]['protocol']


    def get_authentication_types(self, service='http'):
        if not self.is_service_supported(service, multi=False):
            return []
        return self.services[service]['auth_types']


    def get_service_checks(self, service):
        if not self.is_service_supported(service, multi=False):
            return None
        return self.services[service]['checks']      


    def get_service_from_port(self, port, protocol='tcp'):
        """
        Try to get the service name from the port number.
        Research is based on default ports
        :param port: Port number
        :param protocol: By default TCP
        :return: Service name if found, None otherwise
        """
        for service in self.list_services():
            if self.get_default_port(service) == port and self.get_protocol(service) == protocol:
                return service
        return None


    def is_service_supported(self, service, multi=True):
        """
        Check if given service is supported
        :param service: Service name to check
        :param multi: Boolean indicating if "multi" should be considered as valid service name
        """
        return service.lower() in self.list_services(multi)


    def is_existing_check(self, check_name):
        """
        Indicates if a given check name is existing for any supported service (NOT case-sensitive)
        :param check_name: Name of the check to look for
        :return: Boolean
        """
        for svc in self.list_services():
            if self.services[svc]['checks'].is_existing_check(check_name): 
                return True
        return False


    def is_valid_authentication_type(self, auth_type, service='http'):
        return auth_type.lower() in self.get_authentication_types(service)


    def is_specific_option_name_supported(self, option, service=None):
        """
        Check if a given context-specific option name is valid, either for any service
        or for a given service
        :param option: Context-specific option name to check
        :param service: Service name or None if check for any service
        :return: Boolean
        """
        if service is not None and not self.is_service_supported(service, multi=False):
            return False

        services = self.list_services() if service is None else [service]
        for service in services:
            if option in self.services[service]['specific_options'].keys():
                return True
        return False


    def is_specific_option_value_supported(self, name, value):
        """
        Check if the value for a given context-specific option is valid
        :param name: Context-specific option name
        :param value: Context-specific option value
        :return: Boolean
        """
        for service in self.list_services():
            if name in self.services[service]['specific_options'].keys():
                type_ = self.services[service]['specific_options'][name]
                if type_ == OptionType.BOOLEAN:
                    return value in ('true', 'false')
                elif type_ == OptionType.LIST:
                    return value not in self.services[service]['supported_list_options'][name]
                else:
                    return True
        return False


    def get_specific_option_type(self, option, service):
        """
        Get the type of a context-specific option
        :param option: Context-specific option name
        :param service: Service name
        :return: OptionType
        """
        if self.is_specific_option_name_supported(option, service):
            return self.services[service]['specific_options'][option]
        else:
            return None


    def get_service_for_specific_option(self, name):
        """
        Get the service name on which a specific option is applied
        :param name: Context-specific option name
        :return: Service name or None if not found
        """
        for service in self.list_services():
            if name in self.services[service]['specific_options'].keys():
                return service
        return None


    def show_services(self, toolbox):
        """
        Show all supported services along with number of installed tools / total number
        :param toolbox: Toolbox object
        :return: None
        """
        data = list()
        columns = [
            'Service',
            'Default port',
            '# Tools',
            '# Checks',
        ]
        for service in self.list_services(multi=True):
            data.append([
                service,
                'N/A' if service == 'multi' else '{port}/{proto}'.format(
                    port  = self.services[service]['default_port'],
                    proto = self.services[service]['protocol']),
                '{nb_installed}/{nb_tools}'.format(
                    nb_installed = toolbox.nb_tools_installed(service),
                    nb_tools     = toolbox.nb_tools(service)),
                'N/A' if service == 'multi' else self.services[service]['checks'].nb_checks(),
            ])

        Output.title1('Supported services')
        Output.table(columns, data, hrules=False)


    def show_specific_options(self, filter_service=None):
        """
        Show list of available specific option for the given service or all services
        :param filter_service: None or given service
        :return: None
        """
        data = list()
        columns = [
            'Option',
            'Service',
            'Supported values',
        ]
        services = self.list_services() if filter_service is None else [filter_service]
        for service in services:
            options = self.services[service]['specific_options']
            for opt in options:
                if options[opt] == OptionType.BOOLEAN:
                    values = 'true, false'
                elif options[opt] == OptionType.LIST:
                    values = sorted(self.services[service]['supported_list_options'][opt])
                    values = StringUtils.wrap(', '.join(values), 80)
                else:
                    values = '<anything>' 
                data.append([opt, service, values])

        Output.title1('Available context-specific options for {filter}'.format(
            filter='all services' if filter_service is None else 'service ' + filter_service))
        
        if not data:
            logger.warning('No specific option')
        else:
            Output.table(columns, data)


    def show_authentication_types(self, service):
        """
        Show list of authentication types for the given service.
        Actually relevant only for HTTP (for now ?)
        :param service: Service name
        :return: None
        """
        Output.title1('Supported {service} authentication types'.format(service=service.upper()))
        if not self.is_service_supported(service, multi=False):
            logger.warning('The service {service} is not supported'.format(service=service))
        elif not self.services[service]['auth_types']:
            logger.warning('No special authentication type for this service')
        else:
            data = list()
            for t in sorted(self.services[service]['auth_types']):
                data.append([t])
            Output.table(['Authentication types'], data, hrules=False)


    def show_categories(self, filter_service=None):
        """
        Show list of categories of checks for the given service or all services
        :param filter_service: None or given service
        :return: None
        """
        data = list()
        columns = [
            'Category',
            'Services',
        ]
        services = self.list_services() if filter_service is None else [filter_service]
        svcbycat = defaultdict(list)
        for service in services:
            for category in self.services[service]['checks'].categories:
                svcbycat[category].append(service)

        for category in svcbycat:
            data.append([category, StringUtils.wrap(', '.join(svcbycat[category]), 100)])

        Output.table(columns, data)
