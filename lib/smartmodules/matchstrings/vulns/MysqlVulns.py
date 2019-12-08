#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['mysql'] = {

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

    'nmap': {
        'Authentication bypass in MySQL servers\.\s*(\r\n|\r|\n)\|'
        '\s*State: (LIKELY )?VULNERABLE': {
            'name': 'MySQL Authentication Bypass: Remote attackers can bypass '
                    'authentication by repeatedly authenticating with the same '
                    'incorrect password, which eventually causes a token comparison to '
                    'succeed due to an improperly-checked return value.',
            'reference': 'CVE-2012-2122',
            'score': 5.1,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2012-2122',
            'exploit_available': True,
        }

 	},

    'vulners-lookup': {
        '^(?!ID;CVSS;Title;Description;URL;Type)'
        '(?P<m1>\S+?);(?P<m2>\S+?);(?P<m3>.+?);(?P<m4>.+?);(?P<m5>.+?);.+?$': {
            'name': '$4', #'$3: $4',
            'reference': '$1',
            'score': '$2',
            'link': '$5',        
        },
    },
}