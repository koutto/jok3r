#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > StringUtils
###
import colored
import re
import textwrap


class StringUtils:

    @staticmethod
    def clean(string, allowed_specials=('_', '-', '.', ' ')):
        """
        Remove non-alphanumeric characters from a string, except some
        specified ones.

        :param str string: String to clean
        :param list allowed_specials: List of allowed special characters
        :return: Cleaned string
        :rtype: str
        """
        return ''.join(c for c in string if c.isalnum() or c in allowed_specials)


    @staticmethod
    def shorten(string, maxlength):
        """
        Shorten a string if necessary.

        :param str string: String to shorten
        :param int maxlength: Maximum length for the string
        :return: Shortened string
        :rtype: str
        """
        if len(string) <= maxlength:
            return string
        else:
            return textwrap.wrap(string, maxlength)[0]+'...'


    @staticmethod
    def wrap(string, maxlength):
        """
        Wrap a string on multilines.

        :param str string: String to wrap
        :param int maxlength: Maximum length for each line        
        """
        if not string:
            return ''
        else:
            return '\n'.join(textwrap.wrap(string, maxlength))


    @staticmethod
    def remove_non_printable_chars(string):
        """
        Remove non-ASCII chars like chinese chars.

        :param str string: String to clean
        :return: Cleaned string
        :rtype: str
        """
        printable = set(
            """0123456789abcdefghijklmnopqrstuvwxyz""" \
            """ABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ """)
        return ''.join(filter(lambda x: x in printable, string))


    @staticmethod
    def remove_ansi_escape(string):
        """
        Remove ANSI escape sequences from a string.
        
        :param str string: String to process
        :return: Cleaned string
        :rtype: str
        """
        # ansi_regex = r'\x1b(' \
        #      r'(\[\??\d+[hl])|' \
        #      r'([=<>a-kzNM78])|' \
        #      r'([\(\)][a-b0-2])|' \
        #      r'(\[\d{0,2}[ma-dgkjqi])|' \
        #      r'(\[\d+;\d+[hfy]?)|' \
        #      r'(\[;?[hf])|' \
        #      r'(#[3-68])|' \
        #      r'([01356]n)|' \
        #      r'(O[mlnp-z]?)|' \
        #      r'(/Z)|' \
        #      r'(\d+)|' \
        #      r'(\[\?\d;\d0c)|' \
        #      r'(\d;\dR))'
        # ansi_escape = re.compile(ansi_regex, flags=re.IGNORECASE)
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]', flags=re.IGNORECASE)
        return ansi_escape.sub('', string)


    @staticmethod
    def surrounding_text(text, pattern, nb_words):
        """
        Get text surrounding a given pattern.

        :param str text: Text to search in
        :param str pattern: Pattern to look for (accepts wildcard "%")
        :param int nb_words: (Maximum) Number of words to keep before and after
            the pattern
        :return: Matching strings surrounded by specified number of words (before 
            and after)
        :rtype: list(str)
        """
        before = '((\S+)\s+){0,'+str(nb_words)+'}'
        after = '(\s+(\S+)){0,'+str(nb_words)+'}'
        pattern = '\S*(?P<search>{})\S*'.format(pattern.replace('%', '.*?'))
        m = re.finditer('{before}{pattern}{after}'.format(
            before=before,
            pattern=pattern,
            after=after), text, re.MULTILINE|re.IGNORECASE)

        results = list()
        for a in m:
            results.append(a.group(0).replace(a.group('search'), 
                colored.stylize(a.group('search'), 
                    (colored.fg('light_yellow') + colored.attr('bold')))))
        return results