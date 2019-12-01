#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['java-rmi'] = {

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

    'jexboss': {
        #'\[\*\]\s*Checking\s+(?P<m1>.*):\s*\[\s*(EXPOSED|VULNERABLE)\s*\]': 'JBoss: $1 exposed/vulnerable',
        'Captured ICMP traffic:[\s\S]*ICMP echo request.*\n.*ICMP echo reply': {
            'name': 'Java-RMI Deserialize RCE in Tomcat JMX',
            'reference': 'CVE-2016-8735',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-8735',
            'exploit_available': True,
            'exploited': True,
        },
    },

    'jmxbf': {
        '###SUCCESS### - We got a valid connection for: :': {
            'name': 'JMX Authentication disabled '
                    '(com.sun.management.jmxremote.authenticate=false)',
            'score': 7.5,
            'exploit_available': True,
            'exploited': True,
        },
    },

    'metasploit': {
        'java_rmi_server[\s\S]*session [0-9]+ opened': {
            'name': 'Java RMI Server Insecure Default Configuration Java Code Execution '
                    '(allow loading classes from any remote (HTTP) URL)',
            'reference': 'CVE-2011-3556',
            'score': 7.5,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2011-3556',
            'exploit_available': True,
            'exploited': True,
        },
        'java_jmx_server[\s\S]*session [0-9]+ opened': {
            'name': 'Java JMX Server Insecure Configuration Java Code Execution '
                    '(allow loading classes from any remote (HTTP) URL)',
            'reference': 'CVE-2015-2342',
            'score': 10.0,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2015-2342',
            'exploit_available': True,
            'exploited': True,
        },
    },

    'sjet': {
        '(Successfully loaded MBeanSiberas|Loaded de\.siberas\.lab\.SiberasPayload|'
        'Object instance already existed, no need to install it a second time)': {
            'name': 'Java JMX Server Insecure Configuration Java Code Execution '
                    '(allow loading classes from any remote (HTTP) URL)',
            'reference': 'CVE-2015-2342',
            'score': 10.0,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2015-2342',
            'exploit_available': True,
            'exploited': True,
        },
    },

    'ysoserial': {
        'Captured ICMP traffic:[\s\S]*ICMP echo request.*\n.*ICMP echo reply': {
            'name': 'Java RMI Registry Deserialization RCE',
            'score': 10.0,
            'exploit_available': True,
            'exploited': True,
        },
    },

} 