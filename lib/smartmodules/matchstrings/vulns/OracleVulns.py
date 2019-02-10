#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['oracle'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }


    'odat': {
        'The target is vulnerable to a remote TNS poisoning': 'Oracle TNS Poisoning',
        '\]\s*(?P<m1>.*)\s*\?.*\n.*\[\+\]\s*OK': 'Oracle: $1',
    },

} 