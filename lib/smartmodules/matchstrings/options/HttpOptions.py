#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import options_match


# options_match['http'] = {
#   'tool-name': {
#       'match string (?P<m1>\S+) lorem ispum': {
#           'name': 'option-name',
#           'value': 'option-value-$1'
#       }
#   }
# }

options_match['http'] = {
    
    'metasploit': {
        'has (SHAREPOINT )?DAV ENABLED': {
            'name': 'webdav',
            'value': 'true',
        },
    },
    'nmap': {
    	'weblogic-t3-info: T3 protocol in use' {
    		'name': 'weblogic-t3',
    		'value': 'true',
    	}
    }

}