#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > OSUtils
###

class OSUtils:


    @staticmethod
    def os_from_nmap_banner(banner):
        """
        Return OS name that might be contained inside Nmap banner.

        Some examples:
        - ostype: Windows
        - product: Microsoft HTTPAPI... : Microsoft -> Windows
        - product: IBM HTTP Server version: 6.1.0.47 extrainfo: Derived from 
            Apache 2.0.47; Unix -> Linux
        - product: Apache httpd version: 2.4.34 extrainfo: (Red Hat) -> Red Hat Linux
        """
        matches = {
            'Windows': [
                'ostype: windows',
                'microsoft',
            ],
            'Linux': [
                'ostype: linux',
                'ostype: unix',
                'Unix',
            ],
            'Red Hat Linux': [
                'Red Hat',
            ],
            'Ubuntu Linux': [
                'Ubuntu',
            ],
        }

        for os in matches.keys():
            for string in matches[os]:
                if string.lower() in banner.lower():
                    return os

        return ''


    @staticmethod
    def get_device_type(os, os_family, nmap_device_type):
        """
        Try to get device type.

        List of device types returned by Nmap: 
        https://nmap.org/book/osdetect-device-types.html

        :param str os: Full OS name
        :param str os_family: OS Family (e.g. Linux, Windows, FreeBSD...)
        :param str nmap_device_type: Device type as returned by Nmap

        :return: Device type shown in Jok3r
        :rtype: str
        """

        # Device types matching between Nmap and Jok3r
        DEVICE_TYPE_NMAP_TO_JOKER = {
            'general purpose':      'Server',
            'bridge':               'Device',
            'broadband router':     'Device',
            'firewall':             'Firewall',
            'game console':         'Game console',
            'hub':                  'Device',
            'load balancer':        'Device',
            'media device':         'Media',
            'PBX':                  'VoIP',
            'PDA':                  'PDA',
            'phone':                'Mobile',
            'power-device':         'Power device',
            'printer':              'Printer',
            'print server':         'Print server',
            'proxy server':         'Proxy server',
            'remote management':    'Management',
            'router':               'Device',
            'security-misc':        'Firewall',
            'specialized':          'Misc',
            'storage-misc':         'NAS',
            'switch':               'Device',
            'telecom-misc':         'VoIP',
            'terminal':             'Client',
            'terminal server':      'Server',
            'VoIP adapter':         'VoIP',
            'WAP':                  'Device',
            'webcam':               'Webcam',
        }

        # Nmap device type does not differentiate servers and desktops
        # in the category "general purpose". We try to distinguish desktop
        # based on the OS name. Far from being perfect, only handle Windows
        # and MacOS for now...
        os_patterns_desktops = [
            'Mac OS',
            'macOS',
            'Windows',
        ]
        if nmap_device_type == 'general purpose' \
            and os_family in os_patterns_desktops:
                if 'server' in os.lower():
                    return 'Server'
                else:
                    return 'Desktop'

        else:
            # Default to "Server"
            return DEVICE_TYPE_NMAP_TO_JOKER.get(nmap_device_type, 'Server')


    @staticmethod
    def get_os_vendor(os):
        """
        Get OS Vendor from OS name
        :return: OS vendor
        :rtype: str
        """
        matches = {
            # keyword in OS name (case sensitive) -> corresponding OS vendor
            'Android':      'Google',
            'FreeBSD':      'FreeBSD',
            'iOS':          'Apple',
            'IOS':          'Cisco',
            'linux':        'Linux',
            'Linux':        'Linux',
            'Mac OS':       'Apple',
            'macOS':        'Apple',
            'OpenBSD':      'OpenBSD',
            'OS X':         'Apple',
            'Sun Solaris':  'Sun',
            'SunOS':        'Sun',
            'Windows':      'Microsoft',
        }

        for m in matches:
            if m in os:
                return matches[m]

        return ''


    @staticmethod
    def get_os_family(os):
        """
        Get OS Family from OS name
        :return: OS family
        :rtype: str
        """
        matches = {
            # keyword in OS name (case sensitive) -> corresponding OS family
            'Android':      'Android',
            'FreeBSD':      'FreeBSD',
            'iOS':          'iOS',
            'IOS':          'IOS',
            'linux':        'Linux',
            'Linux':        'Linux',
            'Mac OS':       'Mac OS',
            'macOS':        'Mac OS',
            'OpenBSD':      'OpenBSD',
            'OS X':         'OS X',
            'Sun Solaris':  'Solaris',
            'SunOS':        'SunOS',
            'Windows':      'Windows',
        }
        for m in matches:
            if m in os:
                return matches[m]

        return ''