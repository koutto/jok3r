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

    @staticmethod
    def remove_ansi_escape(string):
        """Remove ANSI escape sequences from a string"""
        ansi_regex = r'\x1b(' \
             r'(\[\??\d+[hl])|' \
             r'([=<>a-kzNM78])|' \
             r'([\(\)][a-b0-2])|' \
             r'(\[\d{0,2}[ma-dgkjqi])|' \
             r'(\[\d+;\d+[hfy]?)|' \
             r'(\[;?[hf])|' \
             r'(#[3-68])|' \
             r'([01356]n)|' \
             r'(O[mlnp-z]?)|' \
             r'(/Z)|' \
             r'(\d+)|' \
             r'(\[\?\d;\d0c)|' \
             r'(\d;\dR))'
        ansi_escape = re.compile(ansi_regex, flags=re.IGNORECASE)
        return ansi_escape.sub('', string)

