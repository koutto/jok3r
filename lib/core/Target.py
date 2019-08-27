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
from lib.utils.NetUtils import NetUtils
from lib.utils.OSUtils import OSUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Service import Service, Protocol
from lib.db.Credential import Credential
from lib.db.Option import Option
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.smartmodules.SmartStart import SmartStart
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
        self.initialized_with_url = False

        if not self.service.host.ip or not self.service.host.hostname \
                or not self.service.port:

            if self.service.url:
                self.initialized_with_url = True
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
        self.service.url = WebUtils.remove_ending_slash(self.service.url)
        url = urlparse(self.service.url)

        if NetUtils.is_valid_ip(url.hostname):
            self.service.host.ip = url.hostname
            self.service.host.hostname = url.hostname # updated in smart_check

        else:
            self.service.host.ip = NetUtils.dns_lookup(url.hostname)
            if not self.service.host.ip:
                raise TargetException('Unable to resolve {}'.format(url.hostname))
            self.service.host.hostname = url.hostname

        # Determine port number
        if not self.service.port:
            self.service.port = WebUtils.get_port_from_url(self.service.url)
            if not NetUtils.is_valid_port(self.service.port):
                raise TargetException('Invalid port number {}'.format(self.service.port))


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

            # By default, forge URL with hostname
            self.service.url = '{proto}://{ip}:{port}'.format(
                proto=proto, ip=self.service.host.hostname, port=self.service.port)


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
    # Target checker and information updater

    def smart_check(self, 
                    reverse_dns_lookup=True, 
                    availability_check=True, 
                    nmap_banner_grabbing=True,
                    html_title_grabbing=True,
                    web_technos_detection=True,
                    smart_context_initialize=True):
        """
        Check if the target is reachable and update target information

        :param bool reverse_dns_lookup: Set to True to attempt performing reverse 
            DNS lookup when no hostname is specified (i.e. only IP is known)
        :param bool availability_check: Set to True to check for availability of 
            the target (TCP/UDP port check).
        :param bool nmap_banner_grabbing: Set to True to run Nmap on (TCP) service 
            and update service information (banner) and host information (OS, device)
        :param bool html_title_grabbing: Set to True to retrieve HTML title and HTTP
            response headers if target service is HTTP
        :param bool web_technos_detection: Set to True to run WebTechnoDetector if 
            target service is HTTP
        :param bool smart_context_initialize: Set to True to initialize the context of
            the target using SmartModules, based on information already known

        :return: Availability status (True if up, False otherwise)
        :rtype: bool
        """

        # If no IP, means that DNS lookup has failed
        if not self.service.host.ip: 
            return False

        # Perform reverse DNS lookup if hostname not defined
        # Note: If lookup fails, it fallbacks to IP
        if reverse_dns_lookup:
            if self.service.host.hostname == self.service.host.ip \
                    or self.service.host.hostname == '' \
                    or self.service.host.hostname is None:

                logger.info('Reverse DNS lookup for {ip}...'.format(
                    ip=str(self.service.host.ip)))
                self.__reverse_dns_lookup()


        # Perform service availability check
        if availability_check and self.service.name != 'http':
            logger.info('Check if service is reachable...')
            self.__availability_check()

        # For HTTP, also grab HTML title and HTTP response headers 
        elif (html_title_grabbing or availability_check) \
            and self.service.name == 'http':
            
            logger.info('Check if URL is reachable (grab HTTP response)...')
            self.__grab_html_title_and_headers()
        else:
            self.service.up = True

        # If service not reachable, we can stop here
        if not self.service.up:
            return False

        # Run Nmap against service for banner grabbing, OS info, Device info
        # Only for TCP services, and if no banner already stored in database
        if nmap_banner_grabbing \
           and self.service.up  \
           and self.service.protocol == Protocol.TCP \
           and not self.service.banner:

            logger.info('Grab service info for [{service}] via Nmap...'.format(
                service=self))
            self.__run_nmap()

        # Perform Web technologies detection for HTTP, if no technologies
        # are already stored in database
        if web_technos_detection \
            and self.service.name == 'http' \
            and not self.service.web_technos:

            logger.info('Web technologies detection using Wappalyzer...')
            detector = WebTechnoDetector(self.service.url)
            technos = detector.detect()
            self.service.web_technos = str(technos)
            detector.print_technos()
            
            # # Try to deduce OS from detected web technologies
            # if not self.service.host.os:
            #     detected_os = detector.get_os()
            #     if detected_os:
            #         self.service.host.os = detected_os
            #         self.service.host.os_vendor = OSUtils.get_os_vendor(detected_os)
            #         self.service.host.os_family = OSUtils.get_os_family(detected_os)
            #         self.service.host.type = OSUtils.get_device_type(
            #             self.service.host.os,
            #             self.service.host.os_family,
            #             '')
            #         logger.info('Detected OS from web technologies = {os}'.format(
            #             os=detected_os))

        # Run SmartModules Start to initialize the context of the target based on the
        # information already known (i.e. banner, web technologies...)
        if smart_context_initialize:
            start = SmartStart(self.service)
            start.run()

        return self.service.up


    def __reverse_dns_lookup(self):
        """
        Attempt to perform reverse DNS lookup (i.e. IP -> Hostname)

        Updated in this method:
            - self.service.host.hostname
        """
        hostname = NetUtils.reverse_dns_lookup(self.service.host.ip)

        if hostname != self.service.host.ip:
            logger.info('{ip} -> {hostname}'.format(ip=self.service.host.ip,
                                                    hostname=hostname))
        else:
            logger.info('No DNS name found for IP')

        self.service.host.hostname = hostname


    def __availability_check(self):
        """
        Check if TCP/UDP port is open

        Updated in this method:
            - self.service.up
        """
        if self.service.protocol == Protocol.TCP:
            # For TCP: simple port check
            self.service.up = NetUtils.is_tcp_port_open(
                str(self.service.host.ip), self.service.port)

        else:
            # For UDP: simple port check
            self.service.up = NetUtils.is_udp_port_open(
                str(self.service.host.ip), self.service.port)


    def __grab_html_title_and_headers(self):
        """
        Grab HTML title and HTTP headers for service HTTP.
        This function is also used to check availability of HTTP services.

        Updated in this method:
            - self.service.up
            - self.service.http_headers
            - self.service.html_title
        """
        if self.service.url: 
            # For HTTP: Check URL availability
            try:
                is_reachable, status, resp_headers = WebUtils.is_url_reachable(
                    self.service.url)
                # In case URL is not reachable, we rebuild it using IP and
                # give a new try, i.e. :
                # http(s)://hostname:port/ -> http(s)://ip:port/
                if not is_reachable \
                    and not self.initialized_with_url \
                    and self.service.host.hostname != self.service.host.ip:

                    new_url = WebUtils.replace_hostname_by_ip(
                        self.service.url,
                        self.service.host.ip,
                        self.service.port)

                    is_reachable, status, resp_headers = WebUtils.is_url_reachable(
                        new_url)
                    if is_reachable:
                        self.service.url = new_url

                #print(is_reachable)
                self.service.up = is_reachable
            except:
                self.service.up = False
                return

            # Grab HTML title and HTTP Headers
            if is_reachable:
                if resp_headers:
                    self.service.http_headers = '\n'.join('{}: {}'.format(key,val) \
                        for (key,val) in resp_headers.items())
                else:
                    self.service.http_headers = ''

                if not self.service.html_title:
                    self.service.html_title = WebUtils.grab_html_title(
                        self.service.url)


    def __run_nmap(self):
        """
        Run Nmap against service to retrieve:
            - Service banner
            - OS info (os name, os vendor, os family) if possible
            - Device info (MAC, vendor, device type) if possible

        Updated in this method:
            - self.service.banner
            - self.service.host.os
            - self.service.host.os_vendor
            - self.service.host.os_family
            - self.service.host.mac
            - self.service.host.vendor
            - self.service.host.type
        """
        # Run Nmap scan
        nmap_info = NetUtils.grab_nmap_info(
            str(self.service.host.ip), self.service.port)
        
        # Get original service name as returned by Nmap
        self.service.name_original = nmap_info['service_name']

        # Get banner 
        self.service.banner = NetUtils.clean_nmap_banner(nmap_info['banner'])
        logger.info('Banner = {banner}'.format(banner=self.service.banner))
        
        # Get OS information
        if nmap_info['os']:
            if not self.service.host.os:
                logger.info('Detected OS = {os}'.format(
                    os=nmap_info['os']))

            elif self.service.host.os != nmap_info['os']:
                logger.info('Detected OS has changed = {os}'.format(
                    os=nmap_info['os']))

            self.service.host.os = nmap_info['os']
            self.service.host.os_vendor = nmap_info['os_vendor']
            self.service.host.os_family = nmap_info['os_family']

        # Get device information
        if nmap_info['mac']:
            self.service.host.mac = nmap_info['mac']

        if nmap_info['vendor']:
            self.service.host.vendor = nmap_info['vendor']

        if nmap_info['type']:
            self.service.host.type = nmap_info['type']

        # # Try to deduce OS from banner if possible and not already done by Nmap
        # if not self.service.host.os:
        #     detected_os = OSUtils.os_from_nmap_banner(self.service.banner)
        #     if detected_os:
        #         self.service.host.os = detected_os
        #         self.service.host.os_vendor = OSUtils.get_os_vendor(detected_os)
        #         self.service.host.os_family = OSUtils.get_os_family(detected_os)
        #         logger.info('Detected OS from banner = {os}'.format(os=detected_os))


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