#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import options_match


options_match['java-rmi'] = {
    
    'jmxbf': {
        '###SUCCESS### - We got a valid connection for: :': {
            'name': 'jmx-auth-disabled',
            'value': 'true',
        },
    },
    'nmap': {
        'jmxrmi': {
            'name': 'jmx',
            'value': 'true',
        },
        'ssl': {
            'name': 'rmissl',
            'value': 'true',
        },
    },
    'sjet': {
        'Successfully loaded MBeanSiberas': {
            'name': 'jmx-auth-disabled',
            'value': 'true',
        },
    },

}