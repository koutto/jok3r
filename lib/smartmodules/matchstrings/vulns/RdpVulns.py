#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['rdp'] = {

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

    'rdpscan': {
        '-\s*VULNERABLE\s*': {
            'name': 'RDP BlueKeep Remote Code Execution',
            'reference': 'CVE-2019-0708',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708',
            'exploit_available': True,
        }
    },

} 


