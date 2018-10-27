# -*- coding: utf-8 -*-
###
### Utils > StringUtils
###
import textwrap

class StringUtils:

    @staticmethod
    def clean(string, allowed_specials=('_', '-', '.', ' ')):
        return ''.join(c for c in string if c.isalnum() or c in allowed_specials)

    @staticmethod
    def shorten(string, maxlength):
        if len(string) <= maxlength:
            return string
        else:
            return textwrap.wrap(string, maxlength)[0]+'...'

    @staticmethod
    def wrap(string, maxlength):
        """Wrap on multilines"""
        if not string:
            return ''
        else:
            return '\n'.join(textwrap.wrap(string, maxlength))

    @staticmethod
    def remove_non_printable_chars(string):
        """Remove non-ASCII chars like chinese chars"""
        printable = set("""0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ """)
        return ''.join(filter(lambda x: x in printable, string))

