# -*- coding: utf-8 -*-
###
### SmartModules > Fingerprints > Fingerprint
###
import re

VERSION_REGEXP = '(?P<version>[0-9.]+)?'

class Fingerprint:

    def __init__(self, fingerprints):
        self.fingerprints = fingerprints


    def search_product_name_and_version(self, tool, text):
        """
        Search for patterns into input text to try to detect product name and 
        potentially version number

        :param str tool: Name of the tool that generated the output
        :param str text: Output from the tool
        :return: [vendor_name/]product_name[|version_number]
        :rtype: str
        """
        result = ''

        for name in self.fingerprints:
            if tool in self.fingerprints[name]:
                version_detection = '[VERSION]' in self.fingerprints[name][tool]
                pattern = self.fingerprints[name][tool].replace('[VERSION]', VERSION_REGEXP)
                m = re.search(pattern, text, re.IGNORECASE|re.DOTALL)
                if m:
                    result = name

                    # If version is present, add it as suffix
                    if version_detection:
                        if m.group('version'):
                            result += '|{}'.format(m.group('version'))
                    break

        return result


    def search_product_version_for_name(self, tool, product_name, text):
        """
        Search for version number into input text using patterns for the given
        product name

        :param str tool: Name of the tool that generated the output
        :param str product_name: Product name to check version number for
        :param str text: Output from the tool
        :return: [vendor_name/]product_name[|version_number]
        :rtype: str
        """
        result = product_name.split('|')[0] if '|' in product_name else product_name

        if product_name not in self.fingerprints:
            return result

        if tool not in self.fingerprints[product_name]:
            return result

        pattern = self.fingerprints[product_name][tool].replace('[VERSION]', VERSION_REGEXP)
        m = re.search(pattern, text, re.IGNORECASE|re.DOTALL)
        if m:
            # If version is present, add it as suffix
            if m.group('version'):
                result += '|{}'.format(m.group('version'))
            break
            
        return result            