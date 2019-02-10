#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['mssql'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }


    'msdat': {
        '\]\s*(Can you|You can|Can we|We can)?\s*(?P<m1>.*)\s*\?.*\n.*\[\+\]\s*OK': 'MSSQL: $1',
    },

} 