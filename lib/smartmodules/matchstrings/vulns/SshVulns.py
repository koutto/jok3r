#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['ssh'] = {


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

    'libssh-scanner': {
        'likely VULNERABLE to authentication bypass': {
            'name': 'SSH: Authentication bypass in libssh',
            'reference': 'CVE-2018-10933',
            'score': 9.3,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2018-10933',
            'exploit_available': True,
        },
    },
    'osueta': {
        '\[\+\] User: \S+ exists': {
            'name': 'OpenSSH User Enumeration timing attack',
            'reference': 'CVE-2016-6210',
            'score': 4.3,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-6210',
            'exploit_available': True,
            'exploited': True,
        },
    },
    'ssh-audit': {
        'SSH(-)?1': {
            'name': 'Obsolete SSHv1 detected',
            'score': 7.0,
        },
        '\(cve\)\s*(?P<m1>\S+)\s+--\s*(?P<m2>.*)\n': {
            'name': 'SSH: $2',
            'reference': '$1',
        },
    },
    'ssh-user-enum-cve2018-15473': {
        '\[\+\] \S+ found!': {
            'name': 'OpenSSH user enumeration',
            'reference': 'CVE-2018-15473',
            'score': 5.3,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2018-15473',
            'exploit_available': True,
            'exploited': True,
        },
    },

} 