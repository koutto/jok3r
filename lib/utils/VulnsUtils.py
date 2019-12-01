#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > VulnsUtils
###

class VulnsUtils:

    @staticmethod
    def get_link_from_reference(reference):
        """
        Get link to information related to vulnerability from its reference identifier.

        :param str reference: Reference identifier of vulnerability
        :return: URL
        :rtype: str|None
        """
        if not reference:
            return None

        if reference.lower().startswith('cve'):
            return 'https://nvd.nist.gov/vuln/detail/{}'.format(reference.upper().strip())
        elif reference.lower().startswith('cwe'):
            number = reference[reference.index('-')+1:]
            return 'https://cwe.mitre.org/data/definitions/{}.html'.format(number)
        else:
            return None


    @staticmethod
    def get_reference_from_link(link):
        """
        Get reference identifier from link to information related to vulnerability.

        :param str link: Link to vulnerability information
        :return: Reference identifier
        :rtype: str|None
        """
        if not link:
            return None

        if link.startswith('https://wpvulndb.com/vulnerabilities/'):
            return 'WPVDB-ID:{}'.format(link[link.rindex('/')+1:])
        else:
            return None