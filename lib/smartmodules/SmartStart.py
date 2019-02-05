#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### SmartModules > Smart Start
###
from lib.output.Logger import logger
from lib.smartmodules.ContextUpdater import ContextUpdater
from lib.smartmodules.matchstrings.MatchStrings import *
from lib.smartmodules.webtechnologies.WebTechnoDetector import WebTechnoDetector



class SmartStart:

    def __init__(self, service, sqlsess):
        """
        SmartStart class allows to run code at the beginning of an attack
        against one service (before running any check). It is useful to initialize
        the target's context according to basic information already available (e.g 
        banner, url...) or that can be quickly retrieved from target (e.g. web 
        technologies).

        :param Service service: Target Service db model
        :param Session sqlsess: Sqlalchemy Session
        """
        self.service = service
        self.sqlsess = sqlsess
        self.cu = None # ContextUpdater


    def run(self):
        """Run start method corresponding to target service if available"""
        list_methods = [method_name for method_name in dir(self) \
                                    if callable(getattr(self, method_name))]
        start_method_name = '__start_{}'.format(self.service.name)

        if start_method_name in list_methods:
            logger.smartinfo('SmartStart processing to initialize context...')
            start_method = getattr(self, start_method_name)
            self.cu = ContextUpdater(self.service, self.sqlsess)
            start_method()
            cu.update()


    #------------------------------------------------------------------------------------

    def __start_ftp(self):

        # Try to detect ftp server from Nmap banner
        self.__detect_product_from_banner('ftp-server')


    #------------------------------------------------------------------------------------

    def __start_http(self):

        # Autodetect HTTPS
        if self.service.url.lower().startswith('https://'):
            logger.smartinfo('HTTPS protocol detected from URL')
            self.cu.add_option('https', 'true')

        # Check if HTTP service is protected by .htaccess authentication
        if '401 Unauthorized'.lower() in self.service.http_headers.lower():
            logger.smartinfo('HTTP authentication (htaccess) detected ' \
                '(401 Unauthorized)')
            self.cu.add_option('htaccess', 'true')

        # Try to detect web server from Nmap banner
        self.__detect_product_from_banner('web-server')

        # Try to detect web technologies
        detector = WebTechnoDetector(self.service.url)
        technos = detector.detect()

        for t in technos:
            for prodtype in products_match['http']:
                p = products_match['http'][prodtype]
                for prodname in p:
                    if 'wappalyzer' in p[prodname]:
                        pattern = p[prodname]['wappalyzer']
                    
                        #m = re.search(pattern, t['name'], re.IGNORECASE|re.DOTALL)
                        if pattern.lowercase() in t['name'].lowercase():

                        # If pattern matches, add detected product
                        #if m:
                            # Add version if present
                            version = t['version']

                            logger.smartinfo('Web technology detected using ' \
                                'Wappalyzer: {type} = {name} {version}'.format(
                                    type=prodtype,
                                    name=servername,
                                    version=version))

                            # Add detected product to context
                            self.cu.add_product(prodtype, prodname, version)

                            # Move to next product type if something found
                            break


    #------------------------------------------------------------------------------------

    def __start_ftp(self):

        # Try to detect ftp server from Nmap banner
        self.__detect_product_from_banner('ftp-server')


    #------------------------------------------------------------------------------------

    def __start_mssql(self):

        # Try to detect mssql server from Nmap banner
        self.__detect_product_from_banner('mssql-server')


    #------------------------------------------------------------------------------------

    def __start_mysql(self):

        # Try to detect mysql server from Nmap banner
        self.__detect_product_from_banner('mysql-server')


    #------------------------------------------------------------------------------------

    def __start_oracle(self):

        # Try to detect oracle server from Nmap banner
        self.__detect_product_from_banner('oracle-server')


    #------------------------------------------------------------------------------------

    def __start_postgresql(self):

        # Try to detect postgresql server from Nmap banner
        self.__detect_product_from_banner('postgresql-server')


    #------------------------------------------------------------------------------------

    def __start_ssh(self):

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
                if 'nmap' in p[servername]:
                    pattern = p[servername]['nmap']
                    version_detection = '[VERSION]' in pattern
                    pattern = pattern.replace('[VERSION]', VERSION_REGEXP)
                    
                    m = re.search(pattern, self.service.banner, re.IGNORECASE|re.DOTALL)

                        # If pattern matches banner, add detected product
                        if m:
                            # Add version if present
                            if version_detection:
                                try:
                                    version = m.group('version')
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
                            self.cu.add_product(prodtype, prodname, version)

                            # Stop product detection from banner if something found
                            break


