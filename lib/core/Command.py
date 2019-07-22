#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Command
###
"""

Commands types:
---------------
- INSTALL : Command for tool installation
- UPDATE  : Command for tool update
- CHECK   : Command for tool post-install check
- RUN     : Command used to run tool (to perform security check)

General Tags
------------
[IP]              Target IP
[URL]             Target URL
[HOST]            Target host
[PORT]            Target port
[URIPATH]         URI Path (e.g. /path/foo/bar/ in http://www.site.com/path/foo/bar/)
[PROTOCOL]        Protocol tcp/udp
[SERVICE]         Service name
[TOOLBOXDIR]      Toolbox directory
[WEBSHELLSDIR]    Webshells directory
[WORDLISTSDIR]    Wordlists directory
[LOCALIP]         Local IP address
[DOMAIN]          Root domain name (e.g. site.com)

Bruteforce Options Tags
-----------------------
[USERLIST default="path"]   List of usernames 
[PASSLIST default="path"]   List of passwords
[WEBLIST default="path"]    Wordlist for web content discovery

Default path must be relative to WORDLISTS_DIR

Credentials Tags
----------------
[USERNAME]        Username (ContextRequirements.auth_status=USER_ONLY or POST_AUTH)
[PASSWORD]        Password (ContextRequirements.auth_status=POST_AUTH)

Note: If needed, the command can be duplicated for each username (when 
auth_status=USER_ONLY) or for each couple username/password (when auth_status=
POST_AUTH).

Specific Options Tags
---------------------
- For OptionType.BOOLEAN type:
[OPTION_NAME true="value"]

- For OptionType.LIST type:
[OPTION_NAME element1="val1" element2="val2" ... default="default val" ]
Note: default="default val" is optional, its value is used when the different 
elements value do not match any specific option.

- For OptionType.VAR type:
[OPTION_NAME set="text _VAR_ text" default="default text"]
    - If variable is set, it is replaced by the text into "set" parameter with _VAR_ 
    replaced by the value of the variable.
    - Otherwise, it is replaced by the text into "default" parameter if existing
    (optional parameter).

Where OPTION_NAME is replaced by the specific option name.

Products Tags
-------------
[PRODUCT_TYPE-VENDOR]           Product vendor
[PRODUCT_TYPE-NAME]             Product name
[PRODUCT_TYPE-VERSION]          Product version number
[PRODUCT_TYPE-VERSION_MAJOR]    Product major version number (e.g. 5 for 5.1.2)

Where PRODUCT_TYPE is replaced by the product type (e.g "web_server").

API keys Tags
-------------
[APIKEY name="apikey-name"]     API key value for apikey-name (e.g. vulners)
"""
import re
import regex
import urllib.parse
from tld import get_tld

from lib.core.Config import *
from lib.core.Constants import *
from lib.utils.NetUtils import NetUtils
from apikeys import API_KEYS


class Command:

    def __init__(self, 
                 cmdtype, 
                 cmdline, 
                 context_requirements=None, 
                 services_config=None):
        """
        Construct Command object.

        :param CmdType cmdtype: Type of command (RUN, INSTALL, UPDATE, CHECK)
        :param str cmdline: Raw command line (may includes tags)
        :param ContextRequirements context_requirements: Context requirements (for RUN)
        :param ServicesConfig services_config: Services configuration (for RUN)
        """
        self.cmdtype = cmdtype
        self.cmdline = cmdline # Keep the raw command line with tags untouched
        self.formatted_cmdline = ''
        self.context_requirements = context_requirements
        self.services_config = services_config
        

    def get_cmdline(self, directory, target=None, arguments=None):
        """
        Get the formatted command line, i.e. with the tags replaced by their correct 
        values according to target's information.

        Note: the command-line is prefixed by a "cd" command to move to the correct 
        directory before running the actual command.

        :param str directory: Directory where the command should be run (if empty,
            the current directory is selected)
        :param Target target: Target (for RUN)
        :param ArgumentsParser arguments: Arguments (for RUN)

        :return: Formatted command-line
        :rtype: str
        """
        self.formatted_cmdline = self.cmdline

        if self.cmdtype == CmdType.RUN:

            # Return now is missing parameters
            if target is None \
               or arguments is None \
               or self.context_requirements is None \
               or self.services_config is None:

                return None

            else:
                # General tags replacement
                self.__replace_tag_ip(target.get_ip())
                self.__replace_tag_url(target.get_url())
                self.__replace_tag_uripath(target.get_url())
                self.__replace_tag_domain(target.get_url())
                self.__replace_tag_host(target.get_host(), target.get_ip())
                self.__replace_tag_port(target.get_port())
                self.__replace_tag_protocol(target.get_protocol())
                self.__replace_tag_service(target.get_service_name())
                self.__replace_tag_webshellsdir(WEBSHELLS_DIR)
                self.__replace_tag_wordlistsdir(WORDLISTS_DIR)
                self.__replace_tag_localip()

                # Bruteforce options tags replacement
                self.__replace_tag_bruteforce_option('USERLIST', arguments.args.userlist)
                self.__replace_tag_bruteforce_option('PASSLIST', arguments.args.passlist)
                #self.__replace_tag_bruteforce_option('WEBLIST', arguments.args.weblist)

                # Credentials tags replacement
                self.__replace_tags_credentials(target)

                # Specific options tags replacement
                self.__replace_tags_specific(target)

                # Products tags replacement
                self.__replace_tags_product(target)

                # API keys replacement
                self.__replace_tag_apikey()

        self.__replace_tag_toolboxdir(TOOLBOX_DIR)

        if directory:
            return 'cd {dir}; {cmd}'.format(dir=directory, cmd=self.formatted_cmdline)
        else:
            return self.formatted_cmdline


    #------------------------------------------------------------------------------------
    # General Tags Replacement

    def __replace_tag_ip(self, ip):
        """
        Replace tag [IP] by the target IP in self.formatted_cmdline.

        :param str ip: Target IP address
        """
        pattern = re.compile('\[IP\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(ip, self.formatted_cmdline)


    def __replace_tag_url(self, url):
        """
        Replace tag [URL] by the target URL in self.formatted_cmdline.

        :param str url: Target URL
        """
        if not url: return
        pattern = re.compile('\[URL\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(url, self.formatted_cmdline)

    def __replace_tag_domain(self, url):
        """
        Replace tag [DOMAIN] by the target URL root domain in self.formatted_cmdline.

        :param str url: Target URL
        """
        if not url: return
        pattern = re.compile('\[DOMAIN\]', re.IGNORECASE)
        try:
            res = get_tld(url, as_object=True)
            domain = res.fld
        except Exception as e:
            domain = ''
        self.formatted_cmdline = pattern.sub(domain, self.formatted_cmdline)

    def __replace_tag_uripath(self, url):
        """
        Replace tag [URIPATH] by the target path in self.formatted_cmdline.

        :param str url: Target URL
        """
        if not url: return
        pattern = re.compile('\[URIPATH\]', re.IGNORECASE)
        try:
            o = urllib.parse.urlparse(url)
            uripath = o.path or '/'
        except Exception as e:
            uripath = '/'

        self.formatted_cmdline = pattern.sub(uripath, self.formatted_cmdline)


    def __replace_tag_host(self, host, ip):
        """
        Replace tag [HOST] by the target hostname in self.formatted_cmdline, 
        fallback to target IP if no hostname available.

        :param str host: Target hostname
        :param str ip: Target IP address
        """
        pattern = re.compile('\[HOST\]', re.IGNORECASE)
        if host:
            self.formatted_cmdline = pattern.sub(host, self.formatted_cmdline)
        else:
            self.formatted_cmdline = pattern.sub(ip, self.formatted_cmdline)


    def __replace_tag_port(self, port):
        """
        Replace tag [PORT] by the target port in self.formatted_cmdline.

        :param int port: Target port number
        """
        pattern = re.compile('\[PORT\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(str(port), self.formatted_cmdline)


    def __replace_tag_protocol(self, protocol):
        """
        Replace tag [PROTOCOL] by the target protocol in self.formatted_cmdline.

        :param str protocol: Target protocol (tcp or udp)
        """
        pattern = re.compile('\[PROTOCOL\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(protocol, self.formatted_cmdline)


    def __replace_tag_service(self, service):
        """
        Replace tag [SERVICE] by the target service name in self.formatted_cmdline.

        :param str service: Target service name
        """
        pattern = re.compile('\[SERVICE\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(service, self.formatted_cmdline)     


    def __replace_tag_toolboxdir(self, toolbox_dir):
        """
        Replace tag [TOOLBOXDIR] by the toolbox directory in self.formatted_cmdline.

        :param str toolbox_dir: Toolbox directory
        """
        pattern = re.compile('\[TOOLBOXDIR\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(toolbox_dir, self.formatted_cmdline)


    def __replace_tag_webshellsdir(self, webshells_dir):
        """
        Replace tag [WEBSHELLSDIR] by the webshells directory in self.formatted_cmdline.

        :param str webshells_dir: Webshells directory
        """
        pattern = re.compile('\[WEBSHELLSDIR\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(webshells_dir, self.formatted_cmdline)


    def __replace_tag_wordlistsdir(self, wordlists_dir):
        """
        Replace tag [WORDLISTSDIR] by the wordlists directory in self.formatted_cmdline.

        :param str wordlists_dir: Wordlists directory
        """
        pattern = re.compile('\[WORDLISTSDIR\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(wordlists_dir, self.formatted_cmdline)


    def __replace_tag_localip(self):
        """
        Replace tag [LOCALIP] by the local IP address in self.formatted_cmdline.
        """
        pattern = re.compile('\[LOCALIP\]', re.IGNORECASE)
        self.formatted_cmdline = pattern.sub(NetUtils.get_local_ip_address(), 
                                             self.formatted_cmdline)
         


    #------------------------------------------------------------------------------------
    # Bruteforce Options Tags Replacement

    def __replace_tag_bruteforce_option(self, tagname, arg_value):
        """
        Replace bruteforce option tags in self.formatted_cmdline.

        [USERLIST default="path"]
        [PASSLIST default="path"]
        [WEBLIST default="path"]

        :param str tagname: Tag name (USERLIST, PASSLIST, WEBLIST)
        :param str arg_value: Value passed as argument by user (via --userlist, 
            --passlist, --weblist). None if not available. 
        """
        pattern = re.compile(
            '\['+tagname.upper()+'\s+default\s*=\s*[\'"](?P<default>.*?)[\'"]\s*\]',
            re.IGNORECASE)
        m = pattern.search(self.formatted_cmdline)

        if m:
            # Replace by value passed as argument by user if available
            if arg_value:
                self.formatted_cmdline = pattern.sub(
                    arg_value,
                    self.formatted_cmdline)

            # By default, use the specified value in tag as path
            else:
                self.formatted_cmdline = pattern.sub(
                    WORDLISTS_DIR + '/' + m.group('default'),
                    self.formatted_cmdline)


    #------------------------------------------------------------------------------------
    # Credentials Tags Replacement

    def __replace_tags_credentials(self, target):
        """
        Replace credentials (username/password) in self.formatted_cmdline.
        
        When authentication status (auth_status) in ContextRequirements is set to 
        USER_ONLY, one command per known username is generated (commands are stacked 
        with ;). Similarly when authentication status is set to POST_AUTH, one command 
        per known username/password couple is generated.

        :param Target target: Target
        """
        if self.context_requirements.auth_status not in (USER_ONLY, POST_AUTH): 
            return

        cmd = ''
        if target.service.name == 'http':
            auth_type = self.context_requirements.auth_type
        else:
            auth_type = None

        # Auth status set to USER_ONLY
        if self.context_requirements.auth_status == USER_ONLY:
            usernames = target.get_usernames_only(auth_type)
            for user in usernames:
                cmd += 'echo $(tput bold)Run command for username={username} :' \
                    '$(tput sgr0); '.format(username=user)
                cmd += self.__replace_tag_username(self.formatted_cmdline, user) + '; '

        # Auth status set to POST_AUTH
        elif self.context_requirements.auth_status == POST_AUTH:
            userpass = target.get_userpass(auth_type)
            for user,password in userpass:
                tmp = self.__replace_tag_username(self.formatted_cmdline, user)
                tmp = self.__replace_tag_password(tmp, password)
                cmd += 'echo $(tput bold)Run command for creds={username}:' \
                    '{password} :$(tput sgr0); '.format(
                        username=user, 
                        password=password)
                cmd += tmp + '; '

        if cmd != '':
            self.formatted_cmdline = cmd


    def __replace_tag_username(self, cmd, username):
        """
        Replace tag [USERNAME] in command line.

        :param str cmd: Command line to format
        :param str username: Username to put in command
        :return: Formatted command line
        :rtype: str
        """
        pattern = re.compile('\[USERNAME\]', re.IGNORECASE)
        return pattern.sub(username, cmd)


    def __replace_tag_password(self, cmd, password):
        """
        Replace tag [PASSWORD] in command line.

        :param str cmd: Command line to format
        :param str username: Password to put in command
        :return: Formatted command line
        :rtype: str
        """
        pattern = re.compile('\[PASSWORD\]', re.IGNORECASE)
        return pattern.sub(password, cmd)


    #------------------------------------------------------------------------------------
    # Specific Options Tags Replacement

    def __replace_tags_specific(self, target):
        """
        Replace specific options tags by the correct value in self.formatted_cmdline

        :param Target target: Target
        """
        service = target.get_service_name()
        specific_options = self.services_config[service]['specific_options'].items()

        for option,type_ in specific_options:
            value = target.get_specific_option_value(option)


            if type_ == OptionType.BOOLEAN:
                self.__replace_tag_specific_boolean(option, value)   

            elif type_ == OptionType.LIST:  
                self.__replace_tag_specific_list(option, value)

            elif type_ == OptionType.VAR:
                self.__replace_tag_specific_var(option, value)


    def __replace_tag_specific_boolean(self, name, value):
        """
        Replace tags of a specific option of type BOOLEAN by the correct value in 
        self.formatted_cmdline.

        :param str name: Specific option name
        :param bool value: Specific option value
        """
        try:
            pattern = re.compile(
                r'\['+name.upper()+'\s+true\s*=\s*[\'"](?P<option>.*?)[\'"]\s*\]', 
                re.IGNORECASE)
            m = pattern.search(self.formatted_cmdline)
            if value == True:
                self.formatted_cmdline = pattern.sub(
                    m.group('option'), self.formatted_cmdline)
            else:
                self.formatted_cmdline = pattern.sub(
                    '', self.formatted_cmdline)

        except Exception as e:
            pass            


    def __replace_tag_specific_list(self, name, value):
        """
        Replace tags of a specific option of type LIST by the correct value in 
        self.formatted_cmdline.

        :param str name: Specific option name
        :param str value: Specific option value
        """
        try:
            pattern = regex.compile(
                r'\['+name.upper()+'(?:\s+(?P<name>\w+)\s*=\s*[\'"]' \
                r'(?P<value>[ a-zA-Z0-9_,;:-]*)[\'"])+\s*\]', 
                regex.IGNORECASE)
            m = pattern.search(self.formatted_cmdline)
            capt = m.capturesdict()

            if value is not None:
                replacement = capt['value'][capt['name'].index(value)]
                self.formatted_cmdline = pattern.sub(replacement, self.formatted_cmdline)
            elif 'default' in [e.lower() for e in capt['name']]:
                replacement = capt['value'][capt['name'].index('default')]
                self.formatted_cmdline = pattern.sub(replacement, self.formatted_cmdline)
            else:
                self.formatted_cmdline = pattern.sub('', self.formatted_cmdline)
        except Exception as e:
            pass


    def __replace_tag_specific_var(self, name, value):
        """
        Replace tags of a specific option of type LIST by the correct value in 
        self.formatted_cmdline.

        - If variable is set by user: replace by content of "set" attribute, 
        inside which _VAR_ is replaced by var value
        - Else, if variable is not set by user: replace by content of "default" 
        attribute or ''

        :param str name: Specific option name
        :param str value: Specific option value
        """        
        try:
            pattern = re.compile(
                r'\['+name.upper()+'\s+set\s*=\s*[\'"](?P<set>.*?)[\'"]\s*' \
                r'(default\s*=\s*[\'"](?P<default>.*?)[\'"])?\s*\]', 
                re.IGNORECASE)
            m = pattern.search(self.formatted_cmdline)

            if value is not None:
                replacement = m.group('set').replace('_VAR_', value)
                self.formatted_cmdline = pattern.sub(
                    replacement, self.formatted_cmdline)
            elif 'default' in m.groupdict():
                self.formatted_cmdline = pattern.sub(
                    m.group('default'), self.formatted_cmdline)
            else:
                self.formatted_cmdline = pattern.sub(
                    '', self.formatted_cmdline)
        except Exception as e:
            pass    


    #------------------------------------------------------------------------------------
    # Product Tags Replacement

    def __replace_tags_product(self, target):
        """
        """
        service = target.get_service_name()
        products = self.services_config[service]['products']

        for product_type in products:
            name, version = target.get_product_name_version(product_type)
            name = name or ''
            version = version or ''

            # Handle case where name stores vendor name to avoid ambiguity
            if '/' in name:
                vendor, name = name.split('/', maxsplit=1)
            else:
                vendor = ''

            pattern = re.compile('\['+product_type+'-VENDOR\]', re.IGNORECASE)
            self.formatted_cmdline = pattern.sub(vendor, self.formatted_cmdline)

            pattern = re.compile('\['+product_type+'-NAME\]', re.IGNORECASE)
            self.formatted_cmdline = pattern.sub(name, self.formatted_cmdline)

            pattern = re.compile('\['+product_type+'-VERSION\]', re.IGNORECASE)
            self.formatted_cmdline = pattern.sub(version, self.formatted_cmdline)        

            pattern = re.compile('\['+product_type+'-VERSION_MAJOR\]', re.IGNORECASE)
            self.formatted_cmdline = pattern.sub(version.split('.')[0], 
                self.formatted_cmdline)          
 

    #------------------------------------------------------------------------------------
    # API key Replacement

    def __replace_tag_apikey(self):
        """
        Replace tags of API key - e.g. [APIKEY name="vulners"] - by the corresponding
        value set by user in "apikeys.py".

        Note: Value should never been empty because a check is performed in Check.run()
        before running any check, and checks requiring an API key are skipped when
        the API key is not provided in "apikeys.py"

        :param str name: API key name (e.g. "vulners")
        """        
        try:
            pattern = re.compile(
                r'\[APIKEY\s+name\s*=\s*[\'"](?P<name>.*?)[\'"]\s*\]',
                re.IGNORECASE)
            m = pattern.search(self.formatted_cmdline)

            if m:
                name = m.group('name')

                if name in API_KEYS.keys():
                    self.formatted_cmdline = pattern.sub(
                        API_KEYS[name], self.formatted_cmdline)
                else:
                    self.formatted_cmdline = pattern.sub('', self.formatted_cmdline)

        except Exception as e:
            pass  