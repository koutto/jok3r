# -*- coding: utf-8 -*-
###
### SmartModules > Http Module
###
# from Wappalyzer import Wappalyzer, WebPage
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.utils.Wappalyzer import WebPage
from lib.output.Logger import logger


class HttpModule(SmartModule):

    def __init__(self, services_config):
        super(HttpModule, self).__init__('http', services_config)


    def start(self, service): 

        # Mapping Nmap banner (lowercase) => context-specific option value
        MAPPING_BANNER = {
            'domino': 'lotusdomino',
        }

        # Mapping from Wappalyzer output (lowercase) => context-specific option value
        MAPPING_WAPPALYZER = {
            'apache-tomcat'             : 'tomcat',
            'jboss-application-server'  : 'jboss',
            'jboss-web'                 : 'jboss',
            'lotus-domino'              : 'lotusdomino',

            'microsoft-asp.net'         : 'asp',
            'adobe-coldfusion'          : 'coldfusion',
        }

        result = SmartModuleResult()

        # Autodetect https
        if service.url.lower().startswith('https://'):
            logger.info('HTTPS protocol detected from URL')
            result.add_option('https', 'true')

        # Try to detect server from banner
        if service.banner:
            banner = service.banner.lower()
            detected = None
            for server in self.supported_list_options['server']:
                if server in banner:
                    result.add_option('server', server)
                    detected = server
            for server in MAPPING_BANNER.keys():
                if server in banner:
                    result.add_option('server', server)
                    detected = server
            if detected:
                logger.info('Server detected from banner: {server}'.format(server=detected))

        # Autodetect web technos using Wappalyzer
        try:
            #print(WebPage(service.url).info())
            technos = list(map(lambda x: x.lower().replace(' ','-'), WebPage(service.url).info()['apps'].split(';')))
            logger.smartinfo('Wappalyzer fingerprinting returns: {}'.format(technos))
            for tech in technos:
                if tech in MAPPING_WAPPALYZER.keys():
                    tech = MAPPING_WAPPALYZER[tech]

                if tech in self.supported_list_options['language']:
                    result.add_option('language', tech)
                elif tech in self.supported_list_options['cms']:
                    result.add_option('cms', tech)
                elif tech in self.supported_list_options['server']:
                    result.add_option('server', tech)
        except Exception as e:
            logger.error('Wappalyzer error: {}'.format(e))

        return result

    def clusterd_detect_server(self, cmd_output):
        r = SmartModuleResult()
        m = re.search('Matched .* fingerprints for service (?P<server>[a-zA-Z]+)', cmd_output)
        if m:
            server = m.group('server').lower()
            if server in self.supported_list_options['server']:
                r.add_option('server', server)
        return r

    def wig_detect_cms_server_language(self, cmd_output):
        MAPPING_WIG = {
            'Magento Enterprise Edition': 'magento',
            'ASP.NET': 'asp',
        }
        r = SmartModuleResult()
        try:
            m = re.findall('m([a-zA-Z ]+[a-zA-Z]).*(CMS|Platform)\s+', cmd_output[cmd_output.index('VERSION'):])
            if m:
                for val, typ in m:
                    if val in MAPPING_WIG.keys():
                        val = MAPPING_WIG[val]
                    val = val.replace(' ', '-')

                    if typ == 'CMS':
                        if val.lower() in self.supported_list_options['cms']:
                            r.add_option('cms', val.lower())
                    else:
                        if val.lower() in self.supported_list_options['server']:
                            r.add_option('server', val.lower())
                        elif val.lower() in self.supported_list_options['language']:
                            r.add_option('language', val.lower())
        except:
            pass
        return r

    def cmseek_detect_cms(self, cmd_output):
        r = SmartModuleResult()
        m = re.search('Detected CMS: (?P<cms>[a-zA-Z ]+[a-zA-Z])', cmd_output)
        if m:
            cms = m.group('cms').replace(' ', '-').lower()
            if cms in self.supported_list_options['cms']:
                r.add_option('cms', cms)
        return r

    def wpscan_valid_usernames(self, cmd_output):
        r = SmartModuleResult()
        try:
            m = re.findall('\|\s+[0-9]+\s+\|\s+(\S+)\s+\|.*\|', cmd_output[cmd_output.index('Enumerating usernames'):])
            if m:
                for username in m:
                    r.add_username(username)
        except:
            pass
        return r

    def wpseku_valid_usernames(self, cmd_output):
        r = SmartModuleResult()
        try:
            m = re.findall('\|\s+[0-9]+\s+\|.*\|\s+(\S+)\s+\|', cmd_output[cmd_output.index('Enumerating userds'):])
            if m:
                if 'None' in m:
                    m.remove('None')
                for username in m:
                    r.add_username(username, auth_type='wordpress')
        except:
            pass
        return r

    def wpseku_valid_creds(self, cmd_output):
        #TODO
        r = SmartModuleResult()
        return r

    def changeme_valid_creds(self, cmd_output):
        MAPPING_CHANGEME = {
            'Apache Tomcat'             : 'tomcat',
            'Apache Tomcat Host Manager': 'tomcat',
            'Oracle Glassfish'          : 'glassfish',
            'JBoss AS 6'                : 'jboss',
            'JBoss AS 6 Alt'            : 'jboss',
        }
        r = SmartModuleResult()
        m = re.findall('[+] Found (.*) default cred (.*):(.*)', cmd_output)
        if m:
            for name, username, password in m:
                if name in MAPPING_CHANGEME.keys():
                    name = MAPPING_CHANGEME[name]
                name = name.replace(' ', '-').lower()

                if name in self.auth_types:
                    r.add_credentials(username, password, auth_type=name)
        return r

    def msf_tomcat_enum_usernames(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('Apache Tomcat (.*) found', cmd_output)
        if m:
            for username in m:
                r.add_username(username, auth_type='tomcat')
        return r

    def domiowned_valid_creds(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('^(\S+)\s+(\S+)\s+(Admin|User)\s*$', cmd_output, flags=re.MULTILINE)
        if m:
            for username, password in m:
                r.add_credentials(username, password, auth_type='lotusdomino')
        return r