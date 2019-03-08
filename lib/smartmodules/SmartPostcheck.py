#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### SmartModules > Smart Postcheck
###
import re

from lib.output.Logger import logger
from lib.smartmodules.ContextUpdater import ContextUpdater
from lib.smartmodules.matchstrings.MatchStrings import *


class SmartPostcheck:

    def __init__(self, service, sqlsess, tool_name, cmd_output):
        """
        SmartPostcheck class allows to run code after a check during an attack 
        against one service. It is useful to analyze/process command outputs
        and to update context accordingly.

        :param Service service: Target service db model
        :param Session sqlsess: Sqlalchemy Session
        :param str tool_name: Name of the check that has been run before
        :param str cmd_output: Command output (sanitized / special chars removed)
        """
        self.service = service
        self.sqlsess = sqlsess
        self.tool_name = tool_name
        self.cmd_output = cmd_output
        self.cu = None # ContextUpdater


    def run(self):
        """Run postcheck processing"""

        logger.smartinfo('SmartPostcheck processing to update context...')

        self.cu = ContextUpdater(self.service, self.sqlsess)
        self.__detect_credentials()
        self.__detect_specific_options()
        self.__detect_products()
        self.__detect_vulns()
        self.cu.update()


    #------------------------------------------------------------------------------------

    def __detect_credentials(self):
        """
        Detect usernames/credentials from command output
        Important: A command output might contain several usernames/passwords with the
        same pattern.
        """
        if self.service.name in creds_match.keys():

            if self.tool_name in creds_match[self.service.name].keys():
                p = creds_match[self.service.name][self.tool_name]

                for pattern in p.keys():

                    # Important: Multiple search/match
                    #m = re.search(pattern, self.cmd_output, re.IGNORECASE|re.DOTALL)
                    mall = re.finditer(pattern, self.cmd_output, re.IGNORECASE)

                    # If pattern matches cmd output, extract username/credentials
                    if mall:
                        for m in mall:
                            cred = dict()
                            if 'user' in p[pattern]:
                                cred['user'] = self.__replace_tokens(
                                    p[pattern]['user'], m)
                                if cred['user'] is None:
                                    continue
                            else:
                                logger.smarterror('Invalid matchstring for ' \
                                    'service={service}, tool={tool}: Missing ' \
                                    '"user" key'.format(
                                        service=self.service.name,
                                        tool=self.tool_name))
                                continue

                            if 'pass' in p[pattern]:
                                cred['pass'] = self.__replace_tokens(
                                    p[pattern]['pass'], m)
                                if cred['pass'] is None:
                                    continue

                            if 'type' in p[pattern]:
                                cred['type'] = self.__replace_tokens(
                                    p[pattern]['type'], m)
                                if cred['type'] is None:
                                    continue

                            # Add username/cred to context
                            if 'pass' in cred:
                                self.cu.add_credentials(
                                    username=cred.get('user'),
                                    password=cred.get('pass'),
                                    auth_type=cred.get('type'))
                            else:
                                self.cu.add_username(
                                    username=cred.get('user'),
                                    auth_type=cred.get('type'))


    def __detect_specific_options(self):
        """Detect specific option update from command output"""
        if self.service.name in options_match.keys():

            if self.tool_name in options_match[self.service.name].keys():
                p = options_match[self.service.name][self.tool_name]

                for pattern in p.keys():
                    m = re.search(pattern, self.cmd_output, re.IGNORECASE)

                    # If pattern matches cmd output, update specific option
                    if m:
                        if 'name' in p[pattern]:
                            name = self.__replace_tokens(p[pattern]['name'], m)
                            if name is None:
                                continue
                        else:
                            logger.smarterror('Invalid matchstring for ' \
                                'service={service}, tool={tool}: Missing ' \
                                '"name" key'.format(
                                    service=self.service.name,
                                    tool=self.tool_name))
                            continue

                        if 'value' in p[pattern]:
                            value = self.__replace_tokens(p[pattern]['value'], m)
                            if value is None:
                                continue
                        else:
                            logger.smarterror('Invalid matchstring for ' \
                                'service={service}, tool={tool}: Missing ' \
                                '"value" key'.format(
                                    service=self.service.name,
                                    tool=self.tool_name))
                            continue 

                        # Add specific option to context
                        self.cu.add_option(name, value)                           


    def __detect_products(self):
        """Detect product from command output"""
        if self.service.name in products_match.keys():

            for prodtype in products_match[self.service.name].keys():
                p = products_match[self.service.name][prodtype]
                break_prodnames = False

                for prodname in p.keys():
                
                    if self.tool_name in p[prodname].keys():
                        patterns = p[prodname][self.tool_name]

                        # List of patterns is supported (i.e. several different
                        # patterns for a given tool)
                        if type(pattern) == str:
                            patterns = [ patterns ]

                        for pattern in patterns:
                            version_detection = '[VERSION]' in pattern
                            pattern = pattern.replace('[VERSION]', VERSION_REGEXP)

                            m = re.search(pattern, self.cmd_output, re.IGNORECASE)

                            # If pattern matches cmd output, add detected product
                            # Note: For a given product type, only one name(+version)
                            # can be added.
                            if m:
                                # Add version if present
                                if version_detection:
                                    try:
                                        version = m.group('version')
                                    except:
                                        version = ''
                                else:
                                    version = ''

                                # Add detected product to context
                                self.cu.add_product(prodtype, prodname, version)

                                # Move to next product type if name+version found
                                # If name not found, or only name but not the version 
                                # found, give a try to next pattern if existing
                                if version:
                                    break_prodnames = True
                                    break

                        if break_prodnames:
                            break


    def __detect_vulns(self):
        """
        Detect vulnerability from command output
        Important: A command output might contain several vulnerabilities with the 
        same pattern.
        """
        if self.service.name in vulns_match.keys():

            if self.tool_name in vulns_match[self.service.name].keys():
                p = vulns_match[self.service.name][self.tool_name]

                for pattern in p.keys():

                    # Important: Multiple search/match
                    #m = re.search(pattern, self.cmd_output, re.IGNORECASE)
                    mall = re.finditer(pattern, self.cmd_output, re.IGNORECASE)

                    # Process each match
                    if mall:
                        for m in mall:
                            name = self.__replace_tokens(p[pattern], m)
                            if name is None:
                                continue

                            # Add vulnerability to context
                            self.cu.add_vuln(name)    


    def __replace_tokens(self, string, match):
        """
        Replace tokens $1, $2 ... with the corresponding value of matching group.
        E.g. : $1 <-> (?P<m1>...)

        :param str string: String that may contain some tokens
        :param _sre.SRE_Match match: Match object resulting from re.search()
        :return: String with tokens replaced with correct values (or None in case of
            error)
        :rtype: str|None
        """
        output = string
        for i in range(10):
            token = '${}'.format(i)
            if token in string:
                group = 'm{}'.format(i)

                if group in match.groupdict():
                    # Replace token by value of matching group
                    # If value is None, replace by empty string
                    output = output.replace(token, match.group(group) or '')

                else:
                    logger.smarterror('Invalid matchstring for service={service}, ' \
                        'tool={tool}'.format(
                            service=self.service.name,
                            tool=self.tool_name))
                    return None

            else:
                # Token must be sequentials ($1, $2...)
                break

        return output


