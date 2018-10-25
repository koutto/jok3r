# -*- coding: utf-8 -*-
###
### Core > Target
###
import textwrap
from six.moves.urllib.parse import urlparse

from lib.core.Config import *
from lib.core.Constants import *
from lib.utils.WebUtils import WebUtils
from lib.utils.NetUtils import NetUtils
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Service import Service, Protocol
from lib.db.Credential import Credential
from lib.db.Option import Option
from lib.output.Logger import logger


class Target:
    """
    Embeds info about targeted service along with the specific options that must be applied
    during the attack.
    """

    def __init__(self, service, services_config):
        """
        :param service: db.Service object storing all info related to target service
        :param services_config: ServicesConfig object
        """
        self.service = service
        self.services_config = services_config

        # If necessary, update/forge URL
        # if self.service.name == 'http' and not self.service.url:
        #     self.service.url = '{proto}://{ip}:{port}'.format(
        #         proto ='http',  # TODO: Need for handling https here ?
        #         ip    = self.service.host.ip,
        #         port  = self.service.port)

        if self.service.url: 
            self.__init_with_url()
        else: 
            self.__init_with_ip()   


    def __init_with_url(self):
        """
        """
        self.service.url = WebUtils.add_prefix_http(self.service.url)
        url = urlparse(self.service.url)

        if NetUtils.is_valid_ip(url.hostname):
            self.service.host.ip = url.hostname
            self.service.host.hostname = NetUtils.reverse_dns_lookup(url.hostname)
        else:
            self.service.host.ip = NetUtils.dns_lookup(url.hostname)
            self.service.host.hostname = url.hostname

        if not self.service.port:
            self.service.port = WebUtils.get_port_from_url(self.service.url)


    def __init_with_ip(self):
        """
        """
        if NetUtils.is_valid_ip(self.service.host.ip):
            self.service.host.hostname = NetUtils.reverse_dns_lookup(str(self.service.host.ip))
        else:
            # host.ip actually stores a hostname at this point
            self.service.host.ip = NetUtils.dns_lookup(str(self.service.host.ip)) 
            self.service.host.hostname = self.service.host.ip


    def smart_check(self, grab_banner_nmap=False):
        """
        Check if the target is reachable and update target info
        :return: Boolean indicating status
        """
        # If no IP, means that DNS lookup has failed
        if not self.service.host.ip: 
            return False

        # Simple port checking
        if self.service.url: 
            is_reachable, status, resp_headers = WebUtils.is_url_reachable(self.service.url)
            self.service.up = is_reachable
            if resp_headers:
                self.service.http_headers = '\n'.join("{}: {}".format(key,val) for (key,val) in resp_headers.items())
            else:
                self.service.http_headers = ''
        elif self.service.protocol == Protocol.TCP:
            self.service.up = NetUtils.is_tcp_port_open(str(self.service.host.ip), self.service.port)
        else:
            self.service.up = NetUtils.is_udp_port_open(str(self.service.host.ip), self.service.port)

        # Banner grabbing via Nmap (for TCP only) only if there is no banner already stored in db
        if grab_banner_nmap and self.service.up  and self.service.protocol == Protocol.TCP and not self.service.banner:
            self.service.banner = NetUtils.grab_banner_nmap(str(self.service.host.ip), self.service.port)

        return self.service.up


    def get_ip(self):
        return str(self.service.host.ip)

    def get_url(self):
        return self.service.url

    def get_host(self):
        return self.service.host.hostname

    def get_port(self):
        return self.service.port

    def get_protocol(self):
        proto = {
            Protocol.TCP: 'tcp',
            Protocol.UDP: 'udp'
        }
        return proto[self.service.protocol]

    def get_protocol2(self):
        return self.service.protocol

    def get_service_name(self):
        return self.service.name

    def get_banner(self):
        return self.service.banner

    def get_http_headers(self):
        return self.service.http_headers

    def get_credentials(self):
        return self.service.credentials

    def get_specific_options(self):
        return self.service.options

    def get_mission_name(self):
        return self.service.host.mission.name


    def get_specific_option_value(self, option_name):
        """
        Get the value for a given specific option
        :param option_name: Specific option's name
        :return: The corresponding value if the option is set, otherwise None
        """
        option_type = self.services_config.get_specific_option_type(option_name, self.service.name)
        if option_type is None:
            return None

        # Check if the option is set
        for opt in self.service.options:
            if opt.name == option_name:
                if option_type == OptionType.BOOLEAN:
                    return opt.value.lower() == 'true'
                else:
                    return opt.value

        # If option is not set: for boolean options, default value is "False"
        if self.services_config.get_specific_option_type(option_name, self.service.name) == OptionType.BOOLEAN:
            return False
        else:
            return None


    def get_usernames_only(self, auth_type=None):
        """
        Get the list of usernames with no associated password
        :param auth_type: For HTTP service, authentication type must be specified 
        :return: List of usernames
        """
        if self.service.name == 'http' and auth_type is None: 
            return list()

        usernames = list()
        for cred in self.service.credentials:
            if cred.password is None:
                if self.service.name != 'http' or auth_type == cred.type:
                    usernames.append(cred.username)
        return usernames


    def get_userpass(self, auth_type=None):
        """
        Get the list of credentials (username+password) where both username and
        password are set (no single usernames !)
        :param auth_type: For HTTP service, authentication type must be specified
        :return: List of tuples (username, password)
        """
        if self.service.name == 'http' and auth_type is None: 
            return list()

        userpass = list()
        for cred in self.service.credentials:
            if cred.password is not None:
                if self.service.name != 'http' or auth_type == cred.type:
                    userpass.append((cred.username, cred.password))
        return userpass


    def is_matching_context(self, context):
        """
        Check if required conditions to run a command (ie. Context) are met
        :param context: Context object
        :return: Boolean
        """
        return self.__are_creds_matching_context(context) and \
               self.__are_specific_options_matching_context(context)


    def __are_creds_matching_context(self, context):
        """
        Check if required authentication status defined in Context is met 
        :param context: Context object
        :return: Boolean     
        """
        # When context does not define any auth_status, no restriction on auth level
        if context['auth_status'] == None: 
            return True
        
        auth_type  = context['auth_type'] if self.service.name == 'http' else None
        users_only = self.get_usernames_only(auth_type)
        userpass   = self.get_userpass(auth_type)

        if len(userpass) > 0     : auth_level = POST_AUTH
        elif len(users_only) > 0 : auth_level = USER_ONLY
        else                     : auth_level = NO_AUTH 

        return auth_level == context['auth_status']


    def __are_specific_options_matching_context(self, context):
        """
        Check if required values for specific options defined in Context are met
        :param context: Context object
        :return: Boolean
        """
        status = True
        for required_option in context.keys():
            if required_option in ('auth_type', 'auth_status'):
                continue
                
            type_ = self.services_config[self.get_service_name()]['specific_options'][required_option]
            current_value  = self.get_specific_option_value(required_option)
            required_value = context[required_option]

            # For type OptionType.BOOLEAN:
            # Option      Context      Result (run ?)
            # True        True         True
            # False       True         False
            # True        False        False
            # False       False        True
            # any         None         True   
            if type_ == OptionType.BOOLEAN:
                status &= required_value is None or current_value == required_value

            # For type OptionType.LIST:
            # Option      Context      Result
            # None        val          False
            # val1        val1,val2    True
            # val1        val2,val3    False
            # any         None         True  
            # any         'undefined'  False
            # None        'undefined'  True                 
            elif type_ == OptionType.LIST:
                status &= required_value is None          or \
                          current_value in required_value or \
                          required_value == ['undefined'] and current_value is None

            # For type OptionType.VAR:
            # Option      Context     Result
            # None        True        False
            # non-empty   True        True
            # None        False       True
            # non-empty   False       False
            # any         None        True        
            elif type_ == OptionType.VAR:
                status &= required_value is None or \
                          current_value is None and required_value == False or \
                          current_value is not None and required_value == True

        return status







