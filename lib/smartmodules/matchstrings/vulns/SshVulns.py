#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['ssh'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # } 

    'cvedetails-lookup': {
        '^\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+1': 'CVE-$1 ($2): $3... ($4) - Exploit available',
        '^\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+None': 'CVE-$1 ($2): $3... ($4)',
    },
    'libssh-scanner': {
        'likely VULNERABLE to authentication bypass': 'SSH: Authentication bypass in libssh (CVE-2018-10933)',
    },
    'osueta': {
        '\[\+\] User: \S+ exists': 'OpenSSH User Enumeration timing attack',
    },
    'ssh-audit': {
        'SSH(-)?1': 'Obsolete SSHv1 detected',
        '\(cve\)\s*(?P<m1>\S+)\s+--\s*(?P<m2>.*)\n': 'SSH: $1 - $2',
    },
    'ssh-user-enum-cve2018-15473': {
        '\[\+\] \S+ found!': 'OpenSSH user enumeration (CVE-2018-10933)',
    },

} 