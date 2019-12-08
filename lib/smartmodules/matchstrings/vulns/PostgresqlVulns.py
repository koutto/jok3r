#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['postgresql'] = {

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

    'psql': {
    	'RCE-Exploitable': {
            'name': 'Postresql Post-Authentication Remote Command execution',
            'reference': 'CVE-2019-9193',
            'score': 7.2,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-9193',
            'exploit_available': True,
            'exploited': True,
        },
    },

    'metasploit': {
    	'is vulnerable to CVE-2013-1899': {
            'name': 'Postresql Command-line flag injection: Argument injection '
                    'vulnerability in PostgreSQL 9.2.x before 9.2.4, 9.1.x before 9.1.9, '
                    'and 9.0.x before 9.0.13 allows remote attackers to cause a denial '
                    'of service (file corruption), and allows remote authenticated users '
                    'to modify configuration settings and execute arbitrary code, via a '
                    'connection request using a database name that begins with a "-".',
            'reference': 'CVE-2013-1899',
            'score': 6.5,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2013-1899',
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