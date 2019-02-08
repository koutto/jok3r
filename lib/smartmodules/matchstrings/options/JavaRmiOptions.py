#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import options_match


options_match['java-rmi'] = {
    
    'nmap': {
        'jmxrmi': {
            'name': 'jmx',
            'value': 'true',
        },
        'ssl': {
            'name': 'rmissl',
            'value': 'true',
        }
    },
    'sjet': {
        'name': 'Successfully loaded MBeanSiberas',
        'value': 'true',
    },

}