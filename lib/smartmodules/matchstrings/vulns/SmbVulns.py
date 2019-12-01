#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['smb'] = {

    #     'tool-name': {
    #         'match string (?P<m1>\S+) lorem ispum': {
    #             'name': 'AngularJS Client-Side Template Injection (CSTI)',
    #             'location': '$1', # optional
    #             'reference': 'CWE-79', # optional
    #             'score': '5.3', # must be convertible to float, optional
    #             'link': 'https://cwe.mitre.org/data/definitions/79.html', # optional
    #             'exploit_available': True/'true'/'1'/1, # optional
    #             'exploited': True, # optional
    #         },
    #     }

    'impacket': {
        '(Found writable share (ADMIN|C)\$|'
        'Process cmd\.exe /c ".*?" finished with ErrorCode: 0)': {
            'name': 'Code Execution possible via psexec (Administrative Access to '
                    'remote computer)',
            'exploit_available': True,
            'exploited': True,
        },
    },
    'nmap': {
        'Microsoft Windows system vulnerable to remote code execution '
        '\(MS08-067\)\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': {
            'name': 'MS08-067 RCE: Vulnerability in Server Service Could Allow Remote '
                    'Code Execution',
            'reference': 'MS08-067',
            'score': 10.0,
            'link': 'https://docs.microsoft.com/en-us/security-updates/securitybulletins'
                    '2008/ms08-067',
            'exploit_available': True,
        },

        'Remote Code Execution vulnerability in Microsoft SMBv1 servers \(ms17-010\)\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': 'MS17-010 RCE',
        'SAMBA Remote Code Execution from Writable Share\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': 'SambaCry RCE',
    },
    'metasploit': {
        'VULNERABLE to MS17-010': {
            'MS17-010 RCE',
        },
        'ms08_067_netapi[\s\S]*?Meterpreter session [1-9] open': {
            'name': 'MS08-067 RCE: Vulnerability in Server Service Could Allow Remote '
                    'Code Execution',
            'reference': 'MS08-067',
            'score': 10.0,
            'link': 'https://docs.microsoft.com/en-us/security-updates/securitybulletins'
                    '2008/ms08-067',
            'exploit_available': True,
            'exploited': True,
        },
    },

} 
