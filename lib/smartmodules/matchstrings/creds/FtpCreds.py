#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['ftp'] = {

    'hydra': {
        '\[ftp(s)?\] host: \S+\s+login:\s+(?P<m1>\S+)\s+password: (?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
        },
    },
    'nmap': {
    	'ftp-anon: Anonymous FTP login allowed': {
    		'user': 'anonymous',
    		'pass': '',
    	},
    },

}