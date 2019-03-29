#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Target
###
import textwrap
from six.moves.urllib.parse import urlparse

from lib.core.Config import *
from lib.core.Constants import *
from lib.core.Exceptions import TargetException
from lib.utils.WebUtils import WebUtils
from lib.utils.NetUtils import NetUtils
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Service import Service, Protocol
from lib.db.Credential import Credential
from lib.db.Option import Option
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.webtechdetector.WebTechnoDetector import WebTechnoDetector


class Target:
    """
    Target object contains a Service db object and implements method to:
    - Give access to information about targeted service, 
    - Check availability of targeted service,
    """

    def __init__(self, service, services_config):
        """
        Construct the Target object.

        :param Service service: Service Model
        :param ServicesConfig services_config: Configuration of services
        """
        self.service = service
        self.services_config = services_config

        if not self.service.host.ip or not self.service.host.hostname \
                or not self.service.port:

            if self.service.url: 
                self.__init_with_url()
            else: 
                self.__init_with_ip()   


    def __init_with_url(self):
        """
        Initialize with an URL (when targeting HTTP).
        This method updates: URL, Hostname, IP, Port

        :raises TargetException: Exception raised if DNS lookup fails
        """
        self.service.url = WebUtils.add_prefix_http(self.service.url)
        url = urlparse(self.service.url)

        if NetUtils.is_valid_ip(url.hostname):
            self.service.host.ip = url.hostname
            print(self.service.host.ip)
            self.service.host.hostname = url.hostname # updated in smart_check

        else:
            self.service.host.ip = NetUtils.dns_lookup(url.hostname)
            if not self.service.host.ip:
                raise TargetException('Unable to resolve {}'.format(url.hostname))
            self.service.host.hostname = url.hostname

        if not self.service.port:
            self.service.port = WebUtils.get_port_from_url(self.service.url)


    def __init_with_ip(self):
        """
        Initialize with an IP address or a hostname.
        This method updates: Hostname, IP

        :raises TargetException: Exception raised if DNS lookup fails
        """
        if NetUtils.is_valid_ip(self.service.host.ip):
            self.service.host.hostname = str(self.service.host.ip) 
            # updated in smart_check
        else:
            # host.ip actually stores a hostname at this point, a DNS lookup is needed
            self.service.host.hostname = self.service.host.ip
            self.service.host.ip = NetUtils.dns_lookup(self.service.host.hostname) 
            if self.service.host.ip:
                logger.info('DNS lookup on {hostname} -> IP: {ip}'.format(
                    hostname=self.service.host.hostname, 
                    ip=self.service.host.ip))
            else:
                raise TargetException('Unable to resolve {}'.format(
                    self.service.host.hostname))

        # Forge URL for http services
        if self.service.name == 'http':
            if self.get_specific_option_value('https'):
                proto = 'https'
            else:
                proto = 'http'

            self.service.url = '{proto}://{ip}:{port}'.format(
                proto=proto, ip=self.service.host.ip, port=self.service.port)


    #------------------------------------------------------------------------------------
    # Basic Getters

    def get_ip(self):
        return str(self.service.host.ip)


    def get_url(self):
        return self.service.url


    def get_host(self):
        return self.service.host.hostname


    def get_os(self):
        return self.service.host.os


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


    def get_products(self):
        return self.service.products


    def get_mission_name(self):
        return self.service.host.mission.name


    #------------------------------------------------------------------------------------
    # Context-Information Getters

    def get_specific_option_value(self, option_name):
        """
        Get the value for a given specific option

        :param str option_name: Specific option's name
        :return: The corresponding value if the option is set, otherwise None
        :rtype: str|bool|None
        """
        type_ = self.services_config.get_specific_option_type(
            option_name, self.service.name)
        if type_ is None:
            return None

        # If option is set, return its value
        opt = self.service.get_option(option_name)
        if opt:
            if type_ == OptionType.BOOLEAN:
                return opt.value.lower() == 'true'
            else:
                return opt.value
        # Otherwise, return default value (False for boolean) or None
        else:
            if type_ == OptionType.BOOLEAN:
                return False
            else:
                return None


    def get_product_name_version(self, product_type):
        """
        Get the product name and version for a given product type.
        (e.g for HTTP, for product_type=web_server, it might be product_name=Apache)

        :param str product_type: Product type
        :return: (Product name, version) if present, otherwise (None, None)
        :rtype: tuple
        """
        prod = self.service.get_product(product_type)
        if prod:
            return (prod.name, prod.version)
        else:
            return (None, None)


    def get_usernames_only(self, auth_type=None):
        """
        Get the list of usernames with no associated password

        :param str auth_type: Authentication type (for HTTP only)
        :return: Usernames with no associated password
        :rtype: list
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

        :param str auth_type: Authentication type (for HTTP only)
        :return: Credentials (username, password)
        :rtype: list(tuple)
        """
        if self.service.name == 'http' and auth_type is None: 
            return list()

        userpass = list()
        for cred in self.service.credentials:
            if cred.password is not None:
                if self.service.name != 'http' or auth_type == cred.type:
                    userpass.append((cred.username, cred.password))
        return userpass


    #------------------------------------------------------------------------------------
    # Target availability checker

    def smart_check(self, 
                    reverse_dns=True, 
                    availability_check=True, 
                    grab_banner_nmap=False,
                    web_technos_detection=True):
        """
        Check if the target is reachable and update target information

        :param bool reverse_dns: Set to True to attempt performing reverse DNS lookup 
            when no hostname is specified (only IP)
        :param bool availability_check: Set to True to check for availability of the
            target, and also grab headers and HTML title for HTTP services
        :param bool grab_banner_nmap: Set to True to grab the Nmap banner (for TCP)
        :param bool web_technos_detection: Set to True to run WebTechnoDetector if 
            target service is HTTP
        :return: Result of check
        :rtype: bool
        """

        # If no IP, means that DNS lookup has failed
        if not self.service.host.ip: 
            return False

        # Perform reverse DNS lookup if hostname not defined
        # Note: If lookup fails, it fallbacks to IP
        if reverse_dns:
            if self.service.host.hostname == self.service.host.ip:
                logger.info('Reverse DNS lookup for {ip}...'.format(
                    ip=str(self.service.host.ip)))
                hostname = NetUtils.reverse_dns_lookup(
                    self.service.host.ip)

                if hostname != self.service.host.ip:
                    logger.info('{ip} -> {hostname}'.format(ip=self.service.host.ip,
                                                            hostname=hostname))
                else:
                    logger.info('No DNS name found for IP')

                self.service.host.hostname = hostname


        # Perform availability check
        if availability_check:
            logger.info('Check if service is reachable...')

            # For HTTP: Check URL availability, grab headers, grab HTML title
            if self.service.url: 
                is_reachable, status, resp_headers = WebUtils.is_url_reachable(
                    self.service.url)
                self.service.up = is_reachable

                if is_reachable:
                    if resp_headers:
                        self.service.http_headers = '\n'.join('{}: {}'.format(key,val) \
                            for (key,val) in resp_headers.items())
                    else:
                        self.service.http_headers = ''

                    if not self.service.html_title:
                        self.service.html_title = WebUtils.grab_html_title(
                            self.service.url)
                
            # For any other service: Simple port check
            elif self.service.protocol == Protocol.TCP:
                self.service.up = NetUtils.is_tcp_port_open(
                    str(self.service.host.ip), self.service.port)
            else:
                self.service.up = NetUtils.is_udp_port_open(
                    str(self.service.host.ip), self.service.port)

            if not self.service.up:
                return False

        else:
            self.service.up = True # consider it as up anyway


        # Banner grabbing via Nmap (for TCP only) only if there is no banner 
        # already stored in db
        if grab_banner_nmap \
           and self.service.up  \
           and self.service.protocol == Protocol.TCP \
           and not self.service.banner:

            logger.info('Grab banner for [{service}] via Nmap...'.format(service=self))
            self.service.banner = NetUtils.clean_nmap_banner(
                NetUtils.grab_banner_nmap(str(self.service.host.ip), self.service.port))
            logger.info('Banner: {banner}'.format(banner=self.service.banner))

            # Try to deduce OS from banner if possible
            if not self.service.host.os:
                detected_os = NetUtils.os_from_nmap_banner(self.service.banner)
                if detected_os:
                    self.service.host.os = detected_os
                    logger.info('Detected OS from banner = {os}'.format(os=detected_os))


        # Web technologies detection for HTTP
        if self.service.name == 'http' and web_technos_detection:
            logger.info('Web technologies detection using Wappalyzer...')
            detector = WebTechnoDetector(self.service.url)
            technos = detector.detect()
            self.service.web_technos = str(technos)
            detector.print_technos()


        return self.service.up


    #------------------------------------------------------------------------------------
    # Output methods

    def __repr__(self):
        return 'host {ip} | port {port}/{proto} | service {service}'.format(
            ip=self.get_ip(),
            port=self.get_port(),
            proto=self.get_protocol(),
            service=self.get_service_name())


    def print_http_headers(self):
        """Print HTTP Response Headers if available"""
        if self.get_http_headers():
            logger.info('HTTP Response headers:')
            for l in self.get_http_headers().splitlines():
                Output.print('    | {}'.format(l))
            print()


    def print_context(self):
        """Print target's context information"""

        # Print credentials if available
        if self.get_credentials():
            logger.info('Credentials set for this target:')
            data = list()
            columns = ['Username', 'Password']
            if self.get_service_name() == 'http': columns.append('auth-type')
            for c in self.get_credentials():
                username = '<empty>' if c.username == '' else c.username
                if c.password is None:
                    password = '???'
                else:
                    password = '<empty>' if c.password == '' else c.password

                line = [username, password]
                if self.get_service_name() == 'http': line.append(c.type)
                data.append(line)
            Output.table(columns, data, hrules=False)

        # Print specific options if available
        if self.get_specific_options():
            logger.info('Context-specific options set for this target:')
            data = list()
            columns = ['Option', 'Value']
            for o in self.get_specific_options():
                data.append([o.name, o.value])
            Output.table(columns, data, hrules=False)

        # Print products if available
        if self.get_products():
            logger.info('Products detected for this target:')
            data = list()
            columns = ['Type', 'Name', 'Version']
            for p in self.get_products():
                data.append([p.type, p.name, p.version])
            Output.table(columns, data, hrules=False)

        # Print OS type if available
        if self.get_os():
            logger.info('OS type detected for this target: {os}'.format(
                os=self.get_os()))