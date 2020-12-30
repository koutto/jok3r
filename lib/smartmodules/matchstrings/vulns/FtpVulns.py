#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['ftp'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'cvedetails-lookup': {
        '^\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+1': 'CVE-$1 ($2): $3... ($4) - Exploit available',
        '^\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+None': 'CVE-$1 ($2): $3... ($4)',
    },
    'ftpmap': {
        '\[\+\] Exploit: "(?P<m1>.*)"': '$1',
    },
    'nmap': {
    	'OPIE off-by-one stack overflow\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': 'OPIE off-by-one stack overflow (CVE-2010-1938)',
    	'ProFTPD server TELNET IAC stack overflow\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE': 'ProFTPD server TELNET IAC stack overflow (CVE-2010-4221)',
    },
} 


