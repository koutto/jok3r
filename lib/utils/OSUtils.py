#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > OSUtils
###

class OSUtils:

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