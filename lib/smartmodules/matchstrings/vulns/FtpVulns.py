#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['ftp'] = {

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

    'cvedetails-lookup': {
        '^CVE-(?P<m1>\S+?);(?P<m2>\S+?);(?P<m3>\S+?);(?P<m4>.+?);(?P<m5>\S+?);'
        '(?P<m6>\S+)$': {
            'name': '$4',
            'reference': 'CVE-$1',
            'score': '$2',
            'link': '$5',
            'exploit_available': '$6',
        },
    },

    'ftpmap': {
        '\[\+\] Exploit: "(?P<m1>.*)"': {
            'name': '$1',
            'exploit_available': True,
        },
    },

    'nmap': {
        'OPIE off-by-one stack overflow\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': {
            'name': 'OPIE off-by-one stack overflow',
            'reference': 'CVE-2010-1938',
            'score': 9.3,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2010-1938',
            'exploit_available': True,
        },
        'ProFTPD server TELNET IAC stack overflow\s*(\r\n|\r|\n)\|\s*State: '
        '(LIKELY )?VULNERABLE': {
            'name': 'ProFTPD server TELNET IAC stack overflow',
            'reference': 'CVE-2010-4221',
            'score': 10.0,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2010-4221',
            'exploit_available': True,
        },
    },
} 


