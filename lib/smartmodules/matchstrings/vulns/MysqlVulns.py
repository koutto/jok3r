#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['mysql'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'cvedetails-lookup': {
        'CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s*(?P<m3>.*?)\s*\|\s*(?P<m4>\S+)\s*\|\s*1': 'CVE-$1 ($2): $3... ($4) - Exploit available',
        'CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s*(?P<m3>.*?)\s*\|\s*(?P<m4>\S+)\s*\|\s*None': 'CVE-$1 ($2): $3... ($4)',
    },

} 