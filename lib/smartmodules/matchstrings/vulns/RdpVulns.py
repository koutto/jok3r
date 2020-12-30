#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['rdp'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'rdpscan': {
        '-\s*VULNERABLE\s*': 'RDP CVE-2019-0708 BlueKeep RCE',
    },

} 


