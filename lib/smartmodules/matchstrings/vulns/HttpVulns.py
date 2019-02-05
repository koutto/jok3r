#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['http'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }


    'domiowned': {
        '(?P<m1>.+) does not require authentication': 'Domino - No auth on $1',
    },

    'wpscan': {
        '\[!\] Title: (?P<m1>.*)': 'Wordpress: $1',
    },

    'joomscan': {
        '(\[\+\+\] )?(?P<m1>(.*))\nCVE\s*:\s*(?P<m2>.*)': 'Joomla: $1 - $2',
        'cannot ensure.*\n(Title : (?P<m1>.*)\n)?Reference : (?P<m2>.*)': 'Joomla (possible false positive): $1 - $2',
        'Location.*\n(Title : (?P<m1>.*)\n)?Reference : (?P<m2>.*)': 'Joomla: $1 - $2',
    },

    'jexboss': {
        '\[\*\]\s*Checking\s+(?P<m1>.*):\s*\[\s*(EXPOSED|VULNERABLE)\s*\]': 'JBoss: $1 exposed/vulnerable',
    },

    'loubia': {
        'Malicious packet sent[\s\S]*Captured ICMP traffic:[\s\S]*ICMP echo request.*\n.*ICMP echo reply': 'Weblogic T3: Java Deserialization RCE (CVE-2015-4852)',
    },

    'metasploit': {
        'webdav_internal_ip[\s\S]*Found internal IP in WebDAV response (?P<m1>.*)': 'WebDAV response leaks internal IP: $1',
        'webdav_website_content[\s\S]*Found file or directory in WebDAV response (?P<m1>.*)': 'WebDAV misconfiguration - Webserver discloses its content',
        'http_put[\s\S]*File uploaded:': 'HTTP PUT enabled',
        '\[\+\] \S+:[0-9]+ (?P<m1>.*) \(404\)': 'JBoss: $1',
        '\[\+\] \S+:[0-9]+ Got authentication bypass via HTTP verb tampering': 'JBoss: Auth bypass via HTTP verb tampering',
        'jenkins_enum[\s\S]*does not require authentication \(200\)': 'Jenkins: Authentication disabled',
    },

} 