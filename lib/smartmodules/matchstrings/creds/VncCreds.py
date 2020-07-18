#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['vnc'] = {

    'hydra': {
        '\[vnc\] host: \S+\s+password: (?P<m1>\S*)': {
            'user': '',
            'pass': '$1',
        },
    },
    'nmap': {
    	'Server does not require authentication': {
    		'user': '',
    		'pass': '',
    	},
    },

}