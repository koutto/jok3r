#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['smb'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }


    'nmap': {
        'Microsoft Windows system vulnerable to remote code execution \(MS08-067\)\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': 'MS08-067 RCE',
        'Remote Code Execution vulnerability in Microsoft SMBv1 servers \(ms17-010\)\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': 'MS17-010 RCE',
        'SAMBA Remote Code Execution from Writable Share\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': 'SambaCry RCE',
    },
    'metasploit': {
        'VULNERABLE to MS17-010': 'MS17-010 RCE',
    }

} 
