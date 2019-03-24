#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['ssh'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }


    'libssh-scanner': {
        'likely VULNERABLE to authentication bypass': 'SSH: Authentication bypass in libssh (CVE-2018-10933)',
    },
    'osueta': {
        '\[\+\] User: \S+ exists': 'OpenSSH User Enumeration timing attack',
    },
    'ssh-user-enum-cve2018-15473': {
        '\[\+\] \S+ found!': 'OpenSSH user enumeration (CVE-2018-10933)',
    },

} 