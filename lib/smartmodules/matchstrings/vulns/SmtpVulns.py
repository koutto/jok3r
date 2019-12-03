#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['smtp'] = {

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

    'nmap': {
        'smtp-open-relay: Server is an open relay': {
            'name': 'SMTP Open-relay',
            'score': 5.0,
            'link': 'https://en.wikipedia.org/wiki/Open_mail_relay',
            'exploit_available': True,
        },
        'Exim (CVE-2010-4344): VULNERABLE': {
        	'name': 'SMTP: Exim heap overflow vulnerability',
        	'reference': 'CVE-2010-4344',
        	'score': 9.3,
        	'link': 'https://nvd.nist.gov/vuln/detail/CVE-2010-4344',
        	'exploit_available': True,
        },
        'Exim (CVE-2010-4345): VULNERABLE': {
        	'name': 'SMTP:Exim privileges escalation vulnerability',
        	'reference': 'CVE-2010-4345',
        	'score': 6.9,
        	'link': 'https://nvd.nist.gov/vuln/detail/CVE-2010-4345',
        	'exploit_available': True,
        },
        'VULNERABLE:\s*\n\s*\|\s*(?P<m1>.+?)\s*\n\s*\|\s*State: VULNERABLE\s*\n\s*\|\s*IDs:\s*CVE:(?P<m2>\S+)': {
        	'name': '$1',
        	'reference': '$2',
        },
    },

}