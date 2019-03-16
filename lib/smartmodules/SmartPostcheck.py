#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### SmartModules > Smart Postcheck
###
import re
import regex

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
            Important: output is prepended by command line
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
                    logger.debug('Search for creds pattern: {pattern}'.format(
                        pattern=pattern))

                    if 'user' not in p[pattern]:
                        logger.smarterror('Invalid matchstring for service={service}, ' \
                            ' tool={tool}: Missing "user" key'.format(
                                service=self.service.name,
                                tool=self.tool_name))
                        continue

                    # Matching method
                    if 'meth' in p[pattern] \
                            and p[pattern]['meth'] in ('finditer', 'search'):
                        method = p[pattern]['meth']
                    else:
                        method = p[pattern]['meth']


                    # Perform regexp matching
                    try:
                        if method == 'finditer':
                            m = re.finditer(pattern, self.cmd_output, re.IGNORECASE)
                        else:
                            m = regex.search(pattern, self.cmd_output, regex.IGNORECASE)
                    except Exception as e:
                        logger.warning('Error with matchstring [{pattern}], you should ' \
                            'review it. Exception: {exception}'.format(
                                pattern=pattern, exception=e))
                        break

                    if not m:
                        continue

                    pattern_match = False

                    if method == 'finditer':
                        for match in m:
                            pattern_match = True
                            cred = dict()

                            # Replace tokens in user, pass, type
                            cred['user'] = self.__replace_tokens_from_matchobj(
                                p[pattern]['user'], match)
                            if cred['user'] is None:
                                continue

                            if 'pass' in p[pattern]:
                                cred['pass'] = self.__replace_tokens_from_matchobj(
                                    p[pattern]['pass'], match)
                                if cred['pass'] is None:
                                    continue

                            if 'type' in p[pattern]:
                                cred['type'] = self.__replace_tokens_from_matchobj(
                                    p[pattern]['type'], match)
                                if cred['type'] is None:
                                    continue

                            # Add username/cred to context
                            if 'pass' in cred:
                                self.cu.add_credentials(
                                    username=cred.get('user'),
                                    password=cred.get('pass'),
                                    auth_type=cred.get('type'))
                            elif 'user' in cred:
                                self.cu.add_username(
                                    username=cred.get('user'),
                                    auth_type=cred.get('type'))

                    else:
                        pattern_match = True
                        matchs = m.capturesdict()
                        if 'm1' not in matchs:
                            logger.smarterror('Invalid matchstring for ' \
                                'service={service}, tool={tool}: Missing match ' \
                                'group'.format(
                                    service=self.service.name,
                                    tool=self.tool_name))
                            return

                        nb_groups = len(matchs['m1'])

                        for i in range(nb_groups):
                            cred = dict()

                            # Replace tokens in user, pass, type
                            cred['user'] = self.__replace_tokens_from_captdict(
                                p[pattern]['user'], matchs, i)
                            if cred['user'] is None:
                                continue

                            if 'pass' in p[pattern]:
                                cred['pass'] = self.__replace_tokens_from_captdict(
                                    p[pattern]['pass'], matchs, i)
                                if cred['pass'] is None:
                                    continue

                            if 'type' in p[pattern]:
                                cred['type'] = self.__replace_tokens_from_captdict(
                                    p[pattern]['type'], matchs, i)
                                if cred['type'] is None:
                                    continue

                            # Add username/cred to context
                            if 'pass' in cred:
                                self.cu.add_credentials(
                                    username=cred.get('user'),
                                    password=cred.get('pass'),
                                    auth_type=cred.get('type'))
                            elif 'user' in cred:
                                self.cu.add_username(
                                    username=cred.get('user'),
                                    auth_type=cred.get('type'))

                    # If a pattern has matched, skip the next patterns
                    if pattern_match:
                        logger.debug('Creds pattern matches (user only)')
                        return


    #------------------------------------------------------------------------------------

    def __detect_specific_options(self):
        """Detect specific option update from command output"""
        if self.service.name in options_match.keys():

            if self.tool_name in options_match[self.service.name].keys():
                p = options_match[self.service.name][self.tool_name]

                for pattern in p.keys():
                    logger.debug('Search for option pattern: {pattern}'.format(
                        pattern=pattern))

                    try:
                        m = re.search(pattern, self.cmd_output, re.IGNORECASE)
                    except Exception as e:
                        logger.warning('Error with matchstring [{pattern}], you should '\
                            'review it. Exception: {exception}'.format(
                                pattern=pattern, exception=e))
                        break


                    # If pattern matches cmd output, update specific option
                    if m:
                        logger.debug('Option pattern matches')
                        if 'name' in p[pattern]:
                            name = self.__replace_tokens_from_matchobj(
                                p[pattern]['name'], m)
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
                            value = self.__replace_tokens_from_matchobj(
                                p[pattern]['value'], m)
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


    #------------------------------------------------------------------------------------

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
                        if type(patterns) == str:
                            patterns = [ patterns ]

                        for pattern in patterns:
                            version_detection = '[VERSION]' in pattern
                            pattern = pattern.replace('[VERSION]', VERSION_REGEXP)

                            logger.debug('Search for products pattern: {pattern}'.format(
                                pattern=pattern))

                            try:
                                m = re.search(pattern, self.cmd_output, re.IGNORECASE)
                            except Exception as e:
                                logger.warning('Error with matchstring [{pattern}], ' \
                                    'you should review it. Exception: ' \
                                    '{exception}'.format(
                                        pattern=pattern, exception=e))
                                break

                            # If pattern matches cmd output, add detected product
                            # Note: For a given product type, only one name(+version)
                            # can be added.
                            if m:
                                logger.debug('Product pattern matches')
                                # Add version if present
                                if version_detection:
                                    try:
                                        if m.group('version') is not None:
                                            version = m.group('version')
                                        else:
                                            version = ''
                                        logger.debug('Version detected: {version}'.format(
                                            version=version))
                                    except:
                                        version = ''
                                else:
                                    version = ''

                                # Add detected product to context
                                self.cu.add_product(prodtype, prodname, version)

                                # Move to next product type because only one name 
                                # (potentially with version) is supported per type.
                                # If name not found yet, give a try to next pattern
                                break_prodnames = True
                                break

                        if break_prodnames:
                            break


    #------------------------------------------------------------------------------------

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

                    logger.debug('Search for vulns pattern: {pattern}'.format(
                        pattern=pattern))

                    # Important: Multiple search/match
                    #m = re.search(pattern, self.cmd_output, re.IGNORECASE)
                    try:
                        mall = re.finditer(pattern, self.cmd_output, re.IGNORECASE)
                    except Exception as e:
                        logger.warning('Error with matchstring [{pattern}], you ' \
                            'should review it. Exception: {exception}'.format(
                                pattern=pattern, exception=e))
                        break

                    # Process each match
                    if mall:
                        for m in mall:
                            name = self.__replace_tokens_from_matchobj(p[pattern], m)
                            if name is None:
                                continue

                            # Add vulnerability to context
                            logger.debug('Vuln pattern matches')
                            self.cu.add_vuln(name)    


    #------------------------------------------------------------------------------------

    def __replace_tokens_from_matchobject(self, string, match):
        """
        Replace tokens $1, $2 ... with the corresponding value of matching group.
        E.g. : $1 <-> (?P<m1>...)
        This method is used when the matching method "finditer" is used (default)

        :param str string: String that may contain some tokens ($1, $2 ...)
        :param _sre.SRE_Match match: Match object resulting from re.search()
        :return: String with tokens replaced with correct values (or None in case of
            error)
        :rtype: str|None
        """
        output = string
        for i in range(1,10):
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


    def __replace_tokens_from_captdict(self, string, captdict, index):
        """
        Replace tokens $1, $2 ... with the corresponding value of matching group.
        E.g. : $1 <-> (?P<m1>...)
        This method is used when the matching method "search" is used (default)

        :param str string: String that may contain some tokens ($1, $2 ...)
        :param dict captdict: Captures dict resulting from regex.search().capturesdict()
        :return: String with tokens replaced with correct values (or None in case of
            error)
        :rtype: str|None
        """
        output = string
        for i in range(1,10):
            token = '${}'.format(i)
            if token in string:
                group = 'm{}'.format(i)

                if group in captdict and index < len(captdict[group]):
                    output = output.replace(token, captdict[group][index])
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