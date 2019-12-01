#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['jdwp'] = {

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



    'jdwp-shellifier': {
        'Command successfully executed': {
            'name': 'JDWP RCE: JDWP does not use any authentication and could be abused '
                    'by an attacker to execute arbitrary code',
            'score': 10.0,
            'link': 'https://ioactive.com/hacking-java-debug-wire-protocol-or-how/',
            'exploit_available': True,
            'exploited': True,
        },
    },

} 