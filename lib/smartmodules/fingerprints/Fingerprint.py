# -*- coding: utf-8 -*-
###
### SmartModules > Fingerprints > Fingerprint
###
import re

VERSION_REGEXP = '(?P<version>[0-9.]+)?'

class Fingerprint:

    def __init__(self, fingerprints):
        self.fingerprints = fingerprints


    def search_product_name_and_version(self, text):
        """
        Search for patterns into input text to try to detect product name and 
        potentially version number
        """
        result = ''
        for pattern in self.fingerprints:
            pattern = pattern.replace('[VERSION]', VERSION_REGEXP)
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                result = self.fingerprints[pattern]
                # If version is present, add it as suffix
                if m.group('version'):
                    result += '|{}'.format(m.group('version'))
                break
        return result


    def search_product_name(self, text):
        """
        Search for patterns into input text to try to detect product name
        """
        result = ''
        for pattern in self.fingerprints:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                result = self.fingerprints[pattern]
                break
        return result


    def search_product_version(self, product_name, text):
        """
        Search for version number into input text using patterns for the given
        product name.
        """
        result = product_name.split('|')[0] if '|' in product_name else product_name

        # Fingerprints dict used must have the structure:
        # { product_name : [ list of patterns using "[VERSION]" ] }
        if product_name not in self.fingerprints.keys():
            return result

        for pattern in self.fingerprints[product_name]:
            pattern = pattern.replace('[VERSION]', VERSION_REGEXP)
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                # If version is present, add it as suffix
                if m.group('version'):
                    result += '|{}'.format(m.group('version'))
                break
        return result            