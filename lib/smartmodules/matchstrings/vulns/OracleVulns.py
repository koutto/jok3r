#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['oracle'] = {

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

    'odat': {
        'The target is vulnerable to a remote TNS poisoning': {
            'name': 'Oracle TNS Poisoning: TNS Listener allows remote attackers to '
                    'execute arbitrary database commands by performing a remote '
                    'registration of a database (1) instance or (2) service name that '
                    'already exists, then conducting a man-in-the-middle (MITM) attack '
                    'to hijack database connections, aka "TNS Poison."',
            'reference': 'CVE-2012-1675',
            'score': 7.5,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2012-1675',
            'exploit_available': True,
        },
        '\]\s*(?P<m1>.*)\s*\?.*\n.*\[\+\]\s*OK': {
            'name': 'Oracle Post-Authentication Configuration Check: $1',
            'exploit_available': True,
        },
    },

} 