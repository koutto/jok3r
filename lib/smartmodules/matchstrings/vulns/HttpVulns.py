#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['http'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'angularjs-csti-scanner': {
        'Found\s*.*\s*vulnerable request': 'AngularJS Client-Side Template Injection (CSTI)',
    },
    'clusterd': {
        # -a coldfusion --cf-hash
        'Administrative hash:': 'Coldfusion: Administrative hash disclosure',
        # -a jboss --verb-tamper
        'Vulnerable to verb tampering, attempting to deploy': 'JBoss: Verb Tampering (CVE-2010-0738)',
        # -a railo --rl-pw
        'Fetched encrypted password, decrypting': 'Railo: Password leakage via LFI',
    },
    'domiowned': {
        '(?P<m1>.+) does not require authentication': 'Domino: No auth on $1',
    },
    'iis-shortname-scanner': {
        'Result: Vulnerable': 'IIS short filename (8.3) disclosure vulnerability',
    },
    'exploit-tomcat-cve2017-12617': {
        'Vulnerable to CVE-2017-12617': 'Apache Tomcat JSP Upload Bypass RCE (CVE-2017-12617)',
    },
    'exploit-weblogic-cve2017-3248': {
        '\[\+\] target \S+:\S+ is vulnerable': 'Weblogic RMI Registry UnicastRef Object Java Deserialization RCE (CVE-2017-3248)',
    },
    'exploit-weblogic-cve2017-10271': {
        'Malicious packet sent[\s\S]*Captured ICMP traffic:[\s\S]*ICMP echo request.*\n.*ICMP echo reply': 'Weblogic WLS-WSAT RCE (CVE-2017-10271)',
    },
    'exploit-weblogic-cve2018-2893': {
        'Malicious packet sent[\s\S]*Captured ICMP traffic:[\s\S]*ICMP echo request.*\n.*ICMP echo reply': 'Weblogic Java Deserialization RCE (CVE-2018-2893)',
    },
    'joomlavs': {
        '\[!\] Title: (?P<m1>.*)\n.*Reference: (?P<m2>.*)': 'Joomla: $1 ($2)',
    },
    'joomscan': {
        '(\[\+\+\] )?(?P<m1>(.*))\nCVE\s*:\s*(?P<m2>.*)': 'Joomla: $1 - $2',
        'cannot ensure.*\n(Title : (?P<m1>.*)\n)?Reference : (?P<m2>.*)': 'Joomla (possible false positive): $1 - $2',
        'Location.*\n(Title : (?P<m1>.*)\n)?Reference : (?P<m2>.*)': 'Joomla: $1 - $2',
    },
    'jexboss': {
        '\[\*\]\s*Checking\s+(?P<m1>.*):\s*\[\s*(EXPOSED|VULNERABLE)\s*\]': '$1 vulnerable',
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
        'Unauthenticated Jenkins console vulnerability': 'Jenkins: Unauthenticated Jenkins-CI script console (RCE)',
    },
    'shocker': {
        'looks vulnerable': 'Shellshock (CVE-2014-6271)',
    },
    'struts-pwn-cve2017-9805': {
        'Status:\s+Vulnerable': 'Apache Struts2 REST Plugin XStream RCE (CVE-2017-9805)',
    },
    'struts-pwn-cve2018-11776': {
        'Status:\s+Vulnerable': 'Apache Struts2 RCE CVE-2018-11776',
    },
    'wpscan': {
        '\[!\] Title: (?P<m1>.*)': 'Wordpress: $1',
    },

} 