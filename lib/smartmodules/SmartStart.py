#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### SmartModules > Smart Start
###
import ast
import pprint
import re

from lib.output.Logger import logger
from lib.output.Output import Output
from lib.smartmodules.ContextUpdater import ContextUpdater
from lib.smartmodules.matchstrings.MatchStrings import *



class SmartStart:

    def __init__(self, service):
        """
        SmartStart class allows to run code at the beginning of an attack
        against one service (before running any check). It is useful to initialize
        the target's context according to basic information already available (e.g 
        banner, url...) or that can be quickly retrieved from target (e.g. web 
        technologies).

        :param Service service: Target Service model
        """
        self.service = service
        self.cu = None # ContextUpdater


    def run(self):
        """Run start method corresponding to target service if available"""
        list_methods = [method_name for method_name in dir(self) \
                                    if callable(getattr(self, method_name))]
        start_method_name = 'start_{}'.format(self.service.name)

        if start_method_name in list_methods:
            logger.smartinfo('SmartStart processing to initialize context...')
            start_method = getattr(self, start_method_name)
            self.cu = ContextUpdater(self.service)
            start_method()
            self.cu.update()


    #------------------------------------------------------------------------------------

    def start_ftp(self):

        # Try to detect ftp server from Nmap banner
        self.__detect_product_from_banner('ftp-server')


    #------------------------------------------------------------------------------------

    def start_http(self):

        # Autodetect HTTPS
        if self.service.url.lower().startswith('https://'):
            logger.smartinfo('HTTPS protocol detected from URL')
            self.cu.add_option('https', 'true')

        # Check if HTTP service is protected by .htaccess authentication
        if '401 Unauthorized'.lower() in self.service.http_headers.lower():
            logger.smartinfo('HTTP authentication (htaccess) detected ' \
                '(401 Unauthorized)')
            self.cu.add_option('htaccess', 'true')

        # Try to detect web server and/or appserver from Nmap banner
        self.__detect_product_from_banner('web-server')
        self.__detect_product_from_banner('web-appserver')

        # Try to detect supported products from web technologies
        if self.service.web_technos:
            try:
                technos = ast.literal_eval(self.service.web_technos)
            except Exception as e:
                logger.debug('Error when retrieving "web_technos" field ' \
                    'from db: {}'.format(e))
                technos = list()

            for t in technos:
                for prodtype in products_match['http']:
                    p = products_match['http'][prodtype]
                    for prodname in p:
                        if 'wappalyzer' in p[prodname]:
                            pattern = p[prodname]['wappalyzer']
                        
                            #m = re.search(pattern, t['name'], re.IGNORECASE|re.DOTALL)
                            if pattern.lower() == t['name'].lower():
                                version = t['version']
                                self.cu.add_product(prodtype, prodname, version)

                                # Move to next product type if something found
                                break


    #------------------------------------------------------------------------------------

    def start_ftp(self):

        # Try to detect ftp server from Nmap banner
        self.__detect_product_from_banner('ftp-server')


    #------------------------------------------------------------------------------------

    def start_mssql(self):

        # Try to detect mssql server from Nmap banner
        self.__detect_product_from_banner('mssql-server')


    #------------------------------------------------------------------------------------

    def start_mysql(self):

        # Try to detect mysql server from Nmap banner
        self.__detect_product_from_banner('mysql-server')


    #------------------------------------------------------------------------------------

    def start_oracle(self):

        # Try to detect oracle server from Nmap banner
        self.__detect_product_from_banner('oracle-server')


    #------------------------------------------------------------------------------------

    def start_postgresql(self):

        # Try to detect postgresql server from Nmap banner
        self.__detect_product_from_banner('postgresql-server')


    #------------------------------------------------------------------------------------

    def start_ssh(self):

        # Try to detect ssh server from Nmap banner
        self.__detect_product_from_banner('ssh-server')


    #------------------------------------------------------------------------------------

    def __detect_product_from_banner(self, prodtype):
        """
        Detect product from Nmap banner.
        :param str prodtype: Product type
        """

        if self.service.banner:
            p = products_match[self.service.name][prodtype]
            for servername in p:
                if 'nmap-banner' in p[servername]:
                    pattern = p[servername]['nmap-banner']
                    version_detection = '[VERSION]' in pattern
                    pattern = pattern.replace('[VERSION]', VERSION_REGEXP)
                    
                    try:
                        m = re.search(pattern, self.service.banner, 
                            re.IGNORECASE|re.DOTALL)
                    except Exception as e:
                        logger.warning('Error with matchstring [{pattern}], you should '\
                            'review it. Exception: {exception}'.format(
                                pattern=pattern, exception=e))
                        break

                    # If pattern matches banner, add detected product
                    if m:
                        # Add version if present
                        if version_detection:
                            try:
                                if m.group('version') is not None:
                                    version = m.group('version')
                                else:
                                    version = ''
                            except:
                                version = ''
                        else:
                            version = ''

                        logger.smartinfo('Product detected from banner: {type} = ' \
                            '{name} {version}'.format(
                                type=prodtype,
                                name=servername,
                                version=version))

                        # Add detected product to context
                        self.cu.add_product(prodtype, servername, version)

                        # Stop product detection from banner if something found
                        break


