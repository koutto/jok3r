#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['ftp'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'ftpmap': {
        '\[\+\] Exploit: "(?P<m1>.*)"': '$1',
    }

} 


