#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['mssql'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'cvedetails-lookup': {
        '^\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+1': 'CVE-$1 ($2): $3... ($4) - Exploit available',
        '^\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+None': 'CVE-$1 ($2): $3... ($4)',
    },

    # [1.1] Can the current user become sysadmin with trustworthy database method ?
    # [-] KO
    # [1.2] You can steal hashed passwords ?
    # 12:28:55 WARNING -: Impossible to determine the remote database version from the following version string: 'None'
    # [-] KO
    # [1.3] Can we execute system commands with xpcmdshell (directly) ?
    # [-] KO
    # [1.4] Can we re-enable xpcmdshell to use xpcmdshell ?
    # 12:28:55 WARNING -: Impossible to determine the remote database version from the following version string: 'None'
    # [+] OK
    # 12:28:55 WARNING -: Impossible to determine the remote database version from the following version string: 'None'
    # [1.5] Can you use SQL Server Agent Stored Procedures (jobs) to execute system commands?
    # [-] KO
    # [+] ? (Job or cmd is still running)
    # [1.6] Can you capture a SMB authentication ?
    # [+] ? (perhaps)
    # [1.7] Can you use OLE Automation to read files ?
    # [-] KO
    # [1.8] Can you use OLE Automation to write files ?
    # [-] KO
    # [1.9] Can you use OLE Automation to execute Windows system commands ?
    # [-] KO
    # [1.10] Can you use Bulk Insert to read files ?
    # [-] KO
    # [1.11] Can you use Openrowset to read files ?
    # [-] KO
    # [1.12] Can you connect to remote databases with openrowset ? (useful for dictionary attacks)
    # [+] OK

    'msdat': {
        '\]\s*(Can you|You can|Can we|We can)?\s*(?P<m1>.*)\s*\?.*\n(.*?\n)?.*\[\+\]\s*OK': 'MSSQL: $1',
        'RCE-Exploitable': 'MSSQL: Command execution via xp_cmdshell',
    },

} 