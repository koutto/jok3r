#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import options_match


options_match['ftp'] = {
    
    'service-name-original': {
        'ftps': {
            'name': 'ftps',
            'value': 'true',
        },
    },
    'nmap': {
        'ftps(\s|\.)': {
            'name': 'ftps',
            'value': 'true',
        },
    },

}