#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import os_match


# Wappalyzer handles a some OS 
# Ref: https://www.wappalyzer.com/categories/operating-systems

os_match = {
    'Apple OS X Darwin': {
        'wappalyzer': ['Darwin'],
    },
    'CentOS Linux': {
        'banner': ['CentOS'],
        'wappalyzer': ['CentOS'],
    },
    'Debian Linux': {
        'banner': ['Debian'],
        'wappalyzer': ['Debian'],
    },
    'Fedora Linux': {
        'banner': ['Fedora'],
        'wappalyzer': ['Fedora'],
    },
    'FreeBSD': {
        'banner': ['FreeBSD'],
        'wappalyzer': ['FreeBSD'],
    },
    'Gentoo Linux': {
        'banner': ['Gentoo'],
        'wappalyzer': ['Gentoo'],
    },
    'Linux': {
        'banner': ['ostype: Linux', 'ostype: Unix', 'Unix'],
        'wappalyzer': ['Linux', 'Unix'],
    },
    'Raspbian Linux': {
        'banner': ['Raspbian'],
        'wappalyzer': ['Raspbian'],
    },
    'Red Hat Linux': {
        'banner': ['Red Hat', 'RedHat'],
        'wappalyzer': ['Red Hat'],
    },  
    'SunOS': {
        'banner': ['SunOS'],
        'wappalyzer': ['SunOS'],
    },
    'SUSE Linux': {
        'wappalyzer': ['SUSE'],
    },
    'Ubuntu Linux': {
        'banner': ['Ubuntu'],
        'wappalyzer': ['Ubuntu'],
    },
    'Windows': {
        'banner': ['ostype: Windows', 'Microsoft'],
        'wappalyzer': ['Windows'],
    },
}
