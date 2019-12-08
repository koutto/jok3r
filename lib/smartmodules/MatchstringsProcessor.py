#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### SmartModules > Matchstrings Processor
###
import re
import regex

from lib.output.Logger import logger
from lib.utils.StringUtils import StringUtils
from lib.utils.VulnsUtils import VulnsUtils
from lib.smartmodules.matchstrings.MatchStrings import *


class MatchstringsProcessor:

    def __init__(self, 
    			 service, 
    			 tool_name, 
    			 cmd_output,
    			 context_updater):
        """
        :param Service service: Target service model
        :param str tool_name: Source of the data to process (tool name or other 
        	sources such as banner, original service name, wappalyzer)
        :param str cmd_output: Data to process, most of the time is is command output 
        	(sanitized / special chars removed). In this case, it should be prepended
        	by command line
        :param ContextUpdater context_updater: Context updater object
        """
        self.service = service
        self.tool_name = tool_name
        self.cmd_output = cmd_output or ''
        self.cu = context_updater


    #------------------------------------------------------------------------------------

    def detect_credentials(self):
        """
        Detect usernames/credentials from command output
        Important: A command output might contain several usernames/passwords with the
        same pattern.

        Example method "search":

        >>> text = "
        ... Prefix
        ... Found credentials: 
        ...     admin:pass
        ...     toto:pwd
        ... lorem ipsum
        ... lorem ipsum"
        >>> import regex
        >>> m = regex.search('Pre[\s\S]*?Found credentials:(\s*(?P<m1>\S+):(?P<m2>\S+)\s*\n)+', text)
        >>> matchs = m.capturesdict()
        >>> matchs
        {'m1': ['admin', 'toto'], 'm2': ['pass', 'pwd']}

        >>> m = regex.search('(\[v\] Trying Credentials:\s*(?P<user>\S+)\s*(?P<password>\S+)\s*\n)+', text)
        >>> m.capturesdict()
        {'user': ['Miniwick', 'Miniwick', 'Miniwick', 'Miniwick', 'Miniwick'], 'password': ['password', 'admin', '123456', 'Password1', 'Miniwick']}
        >>> m = regex.search('WordPress[\s\S]*?(\[v\] Trying Credentials:\s*(?P<user>\S+)\s*(?P<password>\S+)\s*\n)+', text)
        >>> m.capturesdict()
        {'user': ['Miniwick', 'Miniwick', 'Miniwick', 'Miniwick', 'Miniwick'], 'password': ['password', 'admin', '123456', 'Password1', 'Miniwick']}

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
                        logger.smarterror('Invalid cred matchstring for ' \
                            'service={service}, tool={tool}: Missing "user" key'.format(
                                service=self.service.name,
                                tool=self.tool_name))
                        continue

                    # Matching method
                    if 'meth' in p[pattern] \
                            and p[pattern]['meth'] in ('finditer', 'search'):
                        method = p[pattern]['meth']
                    else:
                        method = 'finditer'


                    # Perform regexp matching
                    try:
                        if method == 'finditer':
                            m = re.finditer(pattern, 
                                            self.cmd_output, 
                                            re.IGNORECASE|re.MULTILINE)
                        else:
                            m = regex.search(pattern, 
                                             self.cmd_output, 
                                             regex.IGNORECASE)
                    except Exception as e:
                        logger.warning('Error with matchstring [{pattern}], you should ' \
                            'review it. Exception: {exception}'.format(
                                pattern=pattern, exception=e))
                        break

                    if not m:
                        continue

                    pattern_match = False

                    # Method "finditer"
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

                    # Method "search"
                    else:
                        pattern_match = True
                        matchs = m.capturesdict()
                        if 'm1' not in matchs:
                            logger.smarterror('Invalid cred matchstring for ' \
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
                        logger.debug('Creds pattern matches')
                        return


    #------------------------------------------------------------------------------------

    def detect_specific_options(self):
        """
        Detect specific option update from command output
        """
        if self.service.name in options_match.keys():

            if self.tool_name in options_match[self.service.name].keys():
                p = options_match[self.service.name][self.tool_name]

                for pattern in p.keys():
                    logger.debug('Search for option pattern: {pattern}'.format(
                        pattern=pattern))

                    try:
                        m = re.search(pattern, 
                                      self.cmd_output, 
                                      re.IGNORECASE|re.MULTILINE)
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
                            logger.smarterror('Invalid option matchstring for ' \
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
                            logger.smarterror('Invalid option matchstring for ' \
                                'service={service}, tool={tool}: Missing ' \
                                '"value" key'.format(
                                    service=self.service.name,
                                    tool=self.tool_name))
                            continue 

                        # Add specific option to context
                        self.cu.add_option(name, value)                           


    #------------------------------------------------------------------------------------

    def detect_products(self):
        """
        Detect product from command output
        
        IMPORTANT: For a given tool, and for a given product, if there are several 
        matchstrings defined, their order is important because it stops after the 
        first match.
        """
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
                                m = re.search(pattern, 
                                              self.cmd_output, 
                                              re.IGNORECASE|re.MULTILINE)
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
                                            logger.debug('Version detected: ' \
                                                '{version}'.format(version=version))
                                        else:
                                            version = ''
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
                                if version != '':
                                    break

                        if break_prodnames:
                            break


    #------------------------------------------------------------------------------------

    def detect_vulns(self):
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
                        mall = re.finditer(pattern, 
                                           self.cmd_output, 
                                           re.IGNORECASE|re.MULTILINE)
                    except Exception as e:
                        logger.warning('Error with matchstring [{pattern}], you ' \
                            'should review it. Exception: {exception}'.format(
                                pattern=pattern, exception=e))
                        break

                    # Process each match
                    if mall:
                        for m in mall:
                            logger.debug('Vuln pattern matches')

                            # Field "name" (str) - mandatory
                            if 'name' in p[pattern] and \
                                    isinstance(p[pattern]['name'], str):
                                name = self.__replace_tokens_from_matchobj(
                                    p[pattern]['name'], m)
                                if name is None:
                                    continue
                                name = name.strip()
                            else:
                                logger.smarterror('Invalid vuln matchstring for ' \
                                    'service={service}, tool={tool}: Missing ' \
                                    '"name" key'.format(
                                        service=self.service.name,
                                        tool=self.tool_name))
                                continue

                            # Field "location" (str) - optional
                            if 'location' in p[pattern]:
                                if not isinstance(p[pattern]['location'], str):
                                    location = None
                                else:
                                    location = self.__replace_tokens_from_matchobj(
                                        p[pattern]['location'], m)
                            else:
                                location = None

                            # Field "reference" (str) - optional
                            if 'reference' in p[pattern]:
                                if not isinstance(p[pattern]['reference'], str):
                                    reference = None
                                else:
                                    reference = self.__replace_tokens_from_matchobj(
                                        p[pattern]['reference'], m)
                            else:
                                reference = None

                            # Field "score" (str|float) - optional
                            if 'score' in p[pattern]:
                                if isinstance(p[pattern]['score'], float):
                                    score = p[pattern]['score']
                                    if score < 0 or score > 10:
                                        score = None
                                elif isinstance(p[pattern]['score'], str):
                                    score = self.__replace_tokens_from_matchobj(
                                        p[pattern]['score'], m)
                                    if score is not None:
                                        score = StringUtils.convert_to_float(score)
                                else:
                                    score = None
                            else:
                                score = None

                            if score is None and reference is not None:
                                # Try to get score from online service
                                score = VulnsUtils.get_cvss_from_reference(reference)

                            # Field "link" (str) - optional
                            if 'link' in p[pattern]:
                                if not isinstance(p[pattern]['link'], str):
                                    link = None
                                else:
                                    link = self.__replace_tokens_from_matchobj(
                                        p[pattern]['link'], m)
                            else:
                                link = None

                            if not link and reference:
                                # Try to build link from reference identifier
                                link = VulnsUtils.get_link_from_reference(reference)

                            elif link and not reference:
                                # Try to get reference identifier from link
                                reference = VulnsUtils.get_reference_from_link(link)

                            # Field "exploit_available" (str|bool|int) - optional
                            if 'exploit_available' in p[pattern]:
                                if isinstance(p[pattern]['exploit_available'], str):
                                    if p[pattern]['exploit_available'].lower() in (
                                        '0', 'none'):
                                        exploit_available = False
                                    else:
                                        exploit_available = True
                                elif isinstance(p[pattern]['exploit_available'], bool):
                                    exploit_available = p[pattern]['exploit_available']
                                elif isinstance(p[pattern]['exploit_available'], int):
                                    exploit_available = p[pattern]['exploit_available']>0
                                else:
                                    exploit_available = None
                            else:
                                exploit_available = None

                            # Field "exploited" (bool) - optiona
                            if 'exploited' in p[pattern]:
                                if not isinstance(p[pattern]['exploited'], bool):
                                    exploited = False
                                else:
                                    exploited = p[pattern]['exploited']
                            else:
                                exploited = False


                            # Add vulnerability to context
                            self.cu.add_vuln(
                                StringUtils.remove_non_printable_chars(name),
                                location,
                                reference,
                                score,
                                link,
                                exploit_available,
                                exploited)    



    #------------------------------------------------------------------------------------

    def detect_os(self):
        """
        Detect product from command output
        """
        for os in os_match.keys():
            if self.tool_name in os_match[os].keys():
                patterns = os_match[os][self.tool_name]

                if type(patterns) == str:
                    patterns = [ patterns ]

                for pattern in patterns:
                    logger.debug('Search for os pattern: {pattern}'.format(
                        pattern=pattern))
                    
                    try:
                        m = re.search(pattern, self.cmd_output, re.IGNORECASE)
                    except Exception as e:
                        logger.warning('Error with matchstring [{pattern}], ' \
                            'you should review it. Exception: {exc}'.format(
                                pattern=pattern, exc=e))
                        break

                    # If pattern matches, add detected OS
                    if m:
                        logger.debug('OS pattern matches')

                        # Add detected OS to the context
                        self.cu.add_os(os)
                        return


    #------------------------------------------------------------------------------------

    def __replace_tokens_from_matchobj(self, string, match):
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

            # else:
            #     # Token must be sequentials ($1, $2...)
            #     break

        return output


    def __replace_tokens_from_captdict(self, string, captdict, index):
        """
        Replace tokens $1, $2 ... with the corresponding value of matching group.
        E.g. : $1 <-> (?P<m1>...)
        This method is used when the matching method "search" is used

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

            # else:
            #     # Token must be sequentials ($1, $2...)
            #     break

        return output
