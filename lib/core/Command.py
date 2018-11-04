# -*- coding: utf-8 -*-
###
### Core > Command
###
#
# Commands types:
# ---------------
# - CMD_INSTALL : Command for tool installation
# - CMD_UPDATE  : Command for tool update
# - CMD_CHECK   : Command for tool post-install check
# - CMD_RUN     : Command used in actual service checks
#
# Tags supported in all commands:
# -------------------------------
# [TOOLBOXDIR]      Toolbox directory
#
# General tags supported in CMD_RUN commands:
# -------------------------------------------
# [IP]              Target IP
# [URL]             Target URL
# [HOST]            Target host
# [PORT]            Target port
# [PROTOCOL]        Protocol tcp/udp
# [SERVICE]         Service name
# [WEBSHELLSDIR]    Webshells directory
# [WORDLISTSDIR]    Wordlists directory
# [USERNAME]        Username (requires Context with auth_status=USER_ONLY or POST_AUTH)
# [PASSWORD]        Password (requires Context with auth_status=POST_AUTH)
# [LOCALIP]         Local IP address
#
# Specific tags depending on specific options (supported by the service):
# -----------------------------------------------------------------------
# - For OptionType.BOOLEAN type:
# [OPTION_NAME true="value"]
#
# - For OptionType.LIST type:
# [OPTION_NAME element1="val1" element2="val2" ... default="default val" ]
# Note: default="default val" is optional, its value is used when the different 
# elements value do not match any specific option.
#
# - For OptionType.VAR type:
# [OPTION_NAME set="text _VAR_ text" default="default text"]
#   - If variable is set, it is replaced by the text into "set" parameter 
#   with _VAR_ replaced by variable's value.
#   - Otherwise, it is replaced by the text into "default" parameter if existing
#   (optional parameter).
#
# - For OptionType.PRODUCT type:
# [OPTION_NAME-VENDOR]  : Product vendor
# [OPTION_NAME-NAME]    : Product name
# [OPTION_NAME-VERSION] : Product version number
#
# Example for http:
# -----------------
# [SSL true="value"]                    In case SSL should be used, add the specified option. e.g.: [SSL true="--ssl"]
# [CMS cms1="val" cms2="val" ...]       Option specific to CMS. e.g.: [CMS drupal="--type Drupal" joomla="--type Joomla"]
# [TECHNO techno1="val" techno2="val"]  Option specific to technology. e.g.: [TECHNO php="-l php" asp="-l asp"]
# [SERVER server1="val" server2="val"]  Option specific to server. e.g.: [SERVER apache="--serv apache" tomcat="--serv tomcat"]
#
import re
import regex

from lib.core.Config import *
from lib.core.Constants import *
from lib.utils.NetUtils import NetUtils


class Command:

    def __init__(self, cmdtype, cmdline, context=None, services_config=None):
        """
        :param cmdtype: Command type among CMD_RUN, CMD_INSTALL, CMD_UPDATE
        :param cmdline: Command line string
        :param context: Context object to define conditions to meet to run the command (used for CMD_RUN only)
        :param services_config: ServicesConfig object (used for CMD_RUN only)
        """
        self.cmdtype         = cmdtype
        self.cmdline         = cmdline # Keep the raw command line with tags untouched
        self.parsed_cmdline  = ''
        self.context         = context
        self.services_config = services_config
        

    def get_cmdline(self, directory, target=None):
        """
        Return the parsed command line, i.e. with the tags replaced by their correct values
        according to the context.
        Note: the command-line is prefixed by a "cd" command to move in the correct directory 
        before all.
        :param directory: Directory in which the command should be run (if empty: current directory)
        :param target: Target object
        :return: Full parsed command-line
        """
        self.parsed_cmdline = self.cmdline
        if self.cmdtype == CMD_RUN:
            if target is None or self.context is None or self.services_config is None:
                return None
            else:
                self.__replace_tag_ip(target.get_ip())
                self.__replace_tag_url(target.get_url())
                self.__replace_tag_host(target.get_host(), target.get_ip())
                self.__replace_tag_port(target.get_port())
                self.__replace_tag_protocol(target.get_protocol())
                self.__replace_tag_service(target.get_service_name())
                self.__replace_tag_webshellsdir(WEBSHELLS_DIR)
                self.__replace_tag_wordlistsdir(WORDLISTS_DIR)
                self.__replace_tag_localip()
                self.__replace_tags_credentials(target)
                self.__replace_tags_specific(target)

        self.__replace_tag_toolboxdir(TOOLBOX_DIR)

        if directory:
            return 'cd {dir}; {cmd}'.format(dir=directory, cmd=self.parsed_cmdline)
        else:
            return self.parsed_cmdline


    def __replace_tag_ip(self, ip):
        """
        Replace tag [IP] by the target's IP in parsed_cmdline
        :param ip: Target's IP
        """
        pattern = re.compile('\[IP\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(ip, self.parsed_cmdline)


    def __replace_tag_url(self, url):
        """
        Replace tag [URL] by the target's URL in parsed_cmdline
        :param url: Target's URL
        """
        if not url: return
        pattern = re.compile('\[URL\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(url, self.parsed_cmdline)


    def __replace_tag_host(self, host, ip):
        """
        Replace tag [HOST] by the target's hostname in parsed_cmdline, fallback to target's IP
        if hostname is not known/specified
        :param host: Target's host
        """
        pattern = re.compile('\[HOST\]', re.IGNORECASE)
        if host:
            self.parsed_cmdline = pattern.sub(host, self.parsed_cmdline)
        else:
            self.parsed_cmdline = pattern.sub(ip, self.parsed_cmdline)


    def __replace_tag_port(self, port):
        """
        Replace tag [PORT] by the target's port in parsed_cmdline
        :param port: Target's port
        """
        pattern = re.compile('\[PORT\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(str(port), self.parsed_cmdline)


    def __replace_tag_protocol(self, protocol):
        """
        Replace tag [PROTOCOL] by the target's protocol in parsed_cmdline
        :param protocol: Target's protocol
        """
        pattern = re.compile('\[PROTOCOL\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(protocol, self.parsed_cmdline)


    def __replace_tag_service(self, service):
        """
        Replace tag [SERVICE] by the target's service name in parsed_cmdline
        :param service: Target's service name
        """
        pattern = re.compile('\[SERVICE\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(service, self.parsed_cmdline)     


    def __replace_tag_toolboxdir(self, toolbox_dir):
        """
        Replace tag [TOOLBOXDIR] by the toolbox directory in parsed_cmdline
        :param toolbox_dir: Toolbox directory
        """
        pattern = re.compile('\[TOOLBOXDIR\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(toolbox_dir, self.parsed_cmdline)


    def __replace_tag_webshellsdir(self, webshells_dir):
        """
        Replace tag [WEBSHELLSDIR] by the webshells directory in parsed_cmdline
        :param webshells_dir: Webshells directory
        """
        pattern = re.compile('\[WEBSHELLSDIR\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(webshells_dir, self.parsed_cmdline)


    def __replace_tag_wordlistsdir(self, wordlists_dir):
        """
        Replace tag [WORDLISTSDIR] by the wordlists directory in parsed_cmdline
        :param wordlists_dir: Wordlists directory
        """
        pattern = re.compile('\[WORDLISTSDIR\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(wordlists_dir, self.parsed_cmdline)


    def __replace_tag_localip(self):
        pattern = re.compile('\[LOCALIP\]', re.IGNORECASE)
        self.parsed_cmdline = pattern.sub(NetUtils.get_local_ip_address(), self.parsed_cmdline)
         

    def __replace_tags_credentials(self, target):
        """
        Replace credentials (username/password) in parsed_cmdline.
        When authentication status in Context is set to USER_ONLY, one command per known
        username is generated (commands are stacked with ; )
        Similarly when authentication status is set to POST_AUTH, one command per known
        username/password couple is generated.
        :param credentials: Target object
        """
        if self.context['auth_status'] not in (USER_ONLY, POST_AUTH): return

        cmd = ''
        auth_type = self.context['auth_type'] if target.service.name == 'http' else None
        if self.context['auth_status'] == USER_ONLY:
            usernames = target.get_usernames_only(auth_type)
            for user in usernames:
                cmd += self.__replace_tag_username(self.parsed_cmdline, user) + '; '

        elif self.context['auth_status'] == POST_AUTH:
            userpass = target.get_userpass(auth_type)
            for user,password in userpass:
                tmp = self.__replace_tag_username(self.parsed_cmdline, user)
                tmp = self.__replace_tag_password(tmp, password)
                cmd += tmp + '; '

        if cmd != '':
            self.parsed_cmdline = cmd


    def __replace_tag_username(self, cmd, username):
        """
        :param cmd: Command line to edit
        :param username: Username
        :return: The edited command-line
        """
        pattern = re.compile('\[USERNAME\]', re.IGNORECASE)
        return pattern.sub(username, cmd)


    def __replace_tag_password(self, cmd, password):
        """
        :param cmd: Command line to edit
        :param password: Password
        :return: The edited command-line
        """
        pattern = re.compile('\[PASSWORD\]', re.IGNORECASE)
        return pattern.sub(password, cmd)


    def __replace_tags_specific(self, target):
        """
        Replace specific tags by the correct value in parsed_cmdline
        eg. for http :
        [SSL option="value"]
        [CMS cms1="val" cms2="val" ... default="val"]
        """
        for option,type_ in self.services_config[target.service.name]['specific_options'].items():
            value = target.get_specific_option_value(option)
            if type_ == OptionType.BOOLEAN:
                try:
                    pattern = re.compile(r'\['+option.upper()+'\s+true\s*=\s*[\'"](?P<option>.*?)[\'"]\s*\]', re.IGNORECASE)
                    m = pattern.search(self.parsed_cmdline)
                    if value == True:
                        self.parsed_cmdline = pattern.sub(m.group('option'), self.parsed_cmdline)
                    else:
                        self.parsed_cmdline = pattern.sub('', self.parsed_cmdline)
                except Exception as e:
                    pass    

            elif type_ == OptionType.LIST:  
                try:
                    pattern = regex.compile(r'\['+option.upper()+'(?:\s+(?P<name>\w+)\s*=\s*[\'"](?P<value>[ a-zA-Z0-9_,;:-]*)[\'"])+\s*\]', 
                                            regex.IGNORECASE)
                    m = pattern.search(self.parsed_cmdline)
                    capt = m.capturesdict()
                    if value is not None:
                        replacement = capt['value'][capt['name'].index(value)]
                        self.parsed_cmdline = pattern.sub(replacement, self.parsed_cmdline)
                    elif 'default' in [e.lower() for e in capt['name']]:
                        replacement = capt['value'][capt['name'].index('default')]
                        self.parsed_cmdline = pattern.sub(replacement, self.parsed_cmdline)
                    else:
                        self.parsed_cmdline = pattern.sub('', self.parsed_cmdline)
                except Exception as e:
                    pass

            elif option_type == OptionType.VAR:
                try:
                    pattern = re.compile(r'\['+option.upper()+'\s+set\s*=\s*[\'"](?P<set>.*?)[\'"]\s*(default\s*=\s*[\'"](?P<default>.*?)[\'"])?\s*\]', 
                                         re.IGNORECASE)
                    m = pattern.search(self.parsed_cmdline)
                    # If variable is set by user: replace by content of "set" attribute, 
                    # inside which _VAR_ is replaced by var value
                    if value is not None:
                        replacement = m.group('set').replace('_VAR_', value)
                        self.parsed_cmdline = pattern.sub(replacement, self.parsed_cmdline)
                    # Else, if variable is not set by user: replace by content of "default" attr or ''
                    elif 'default' in m.groupdict():
                        self.parsed_cmdline = pattern.sub(m.group('default'), self.parsed_cmdline)
                    else:
                        self.parsed_cmdline = pattern.sub('', self.parsed_cmdline)
                except Exception as e:
                    pass    

            elif option_type == OptionType.PRODUCT:
                if value is not None:
                    vendor, name, version = VersionUtils.extract_vendor_name_version(value)
                    # vendor and/or version can be empty string depending on the option value
                    self.parsed_cmdline = self.parsed_cmdline.replace('['+option.upper()+'-VENDOR]', vendor)
                    self.parsed_cmdline = self.parsed_cmdline.replace('['+option.upper()+'-NAME', name)
                    self.parsed_cmdline = self.parsed_cmdline.replace('['+option.upper()+'-VERSION', version)


        # def __remove_args(self):
        #     """
        #     NOT USED ANYMORE
        #     Remove arguments from command line
        #     Example:
        #         - input:  sudo python toolname.py -a 'abc' -b 'def' -c
        #         - output: sudo python toolname.py
        #     """
        #     cmdsplit = self.cmdline.strip().split(' ')
        #     newcmd = ''

        #     if cmdsplit[0].lower() == 'sudo' and len(cmdsplit) > 1:
        #         newcmd = 'sudo '
        #         cmdsplit = cmdsplit[1:]

        #     newcmd += cmdsplit[0]
        #     if cmdsplit[0].lower() in ('python', 'python3', 'perl', 'ruby') and len(cmdsplit) > 1:
        #         if cmdsplit[1] != '-m':
        #             newcmd += ' ' + cmdsplit[1]
        #         elif len(cmdsplit) > 2:
        #             newcmd += ' -m ' + cmdsplit[2]

        #     elif cmdsplit[0].lower() == 'java' and len(cmdsplit) > 1:
        #         if cmdsplit[1] != '-jar':
        #             newcmd += ' ' + cmdsplit[1]
        #         elif len(cmdsplit) > 2:
        #             newcmd += ' -jar ' + cmdsplit[2]

        #     return newcmd