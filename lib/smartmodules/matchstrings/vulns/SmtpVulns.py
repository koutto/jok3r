#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['smtp'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # } 

    'nmap': {
        'smtp-open-relay: Server is an open relay': 'SMTP Open-relay',
        'Exim (CVE-2010-4344): VULNERABLE': 'SMTP: Exim heap overflow vulnerability (CVE-2010-4344)',
        'Exim (CVE-2010-4345): VULNERABLE': 'SMTP:Exim privileges escalation vulnerability (CVE-2010-4345)',
        'VULNERABLE:\s*\n\s*\|\s*(?P<m1>.+?)\s*\n\s*\|\s*State: VULNERABLE\s*\n\s*\|\s*IDs:\s*CVE:(?P<m2>\S+)': '$1 ($2)',
    },

}