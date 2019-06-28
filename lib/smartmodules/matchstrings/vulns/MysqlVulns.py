#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['mysql'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'cvedetails-lookup': {
        '\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+1': 'CVE-$1 ($2): $3... ($4) - Exploit available',
        '\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+None': 'CVE-$1 ($2): $3... ($4)',
    },
    'nmap': {
        'Authentication bypass in MySQL servers\.\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': 'MySQL Authentication Bypass (CVE-2012-2122)',
 	}
}