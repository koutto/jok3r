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
        'Vulnerable to verb tampering, attempting to deploy': 'JBoss: Auth bypass via HTTP verb tampering (CVE-2010-0738)',
        # -a railo --rl-pw
        'Fetched encrypted password, decrypting': 'Railo: Password leakage via LFI',
        # -a axis2 --deploy
        'deployed successfully to /axis2/services': 'Axis2: Web shell deployment possible',
        # -a coldfusion --deploy
        'Deployed.  Access /userfiles/file': 'Coldfusion: FCKEditor exposed',
        '-a coldfusion --deploy[\s\S]*?(deployed at|deployed to|Deployed\.  Access /CFIDE/ad123.cfm)': 'Coldfusion: Web shell deployment possible',
        # -a glassfish --deploy
        '-a glassfish --deploy[\s\S]*?Deployed .* to': 'Glassfish: Web shell deployment possible',
        # -a jboss --deploy
        '-a jboss --deploy[\s\S]*?(deployed to|Successfully deployed)': 'JBoss: Web shell deployment possible',
        # -a railo --deploy
        '-a railo --deploy[\s\S]*?deployed at': 'Railo: Web shell deployment possible',
        # -a tomcat --deploy
        '-a tomcat --deploy[\s\S]*?(Deployed .* to /|is already deployed)': 'Tomcat: Web shell deployment possible',
        # -a weblogic --deploy
        '-a weblogic --deploy[\s\S]*?deployed at': 'Weblogic: Web shell deployment possible',
    },
    'cvedetails-lookup': {
        'CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s*(?P<m3>.*?)\s*\|\s*(?P<m4>\S+)\s*\|\s*1': 'CVE-$1 ($2): $3... ($4) - Exploit available',
        'CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s*(?P<m3>.*?)\s*\|\s*(?P<m4>\S+)\s*\|\s*None': 'CVE-$1 ($2): $3... ($4)',
    },
    'domiowned': {
        '(?P<m1>.+) does not require authentication': 'Domino: No auth on $1',
    },
    'iis-shortname-scanner': {
        'Result: Vulnerable': 'IIS short filename (8.3) disclosure vulnerability',
    },
    'exploit-weblogic-cve2017-3248': {
        '\[\+\] target \S+:\S+ is vulnerable': 'Weblogic RMI Registry UnicastRef Object Java Deserialization RCE (CVE-2017-3248)',
    },
    'jok3r-scripts': {
        'Weblogic T3 Deserialize CVE-2015-4852 Exploit[\s\S]*?Malicious packet sent[\s\S]*?Captured ICMP traffic:[\s\S]*?ICMP echo request.*\n.*ICMP echo reply': 'Weblogic T3: Java Deserialization RCE (CVE-2015-4852)',
        'Weblogic WLS-WSAT RCE CVE-2017-10271 Exploit[\s\S]*?Malicious packet sent[\s\S]*?Captured ICMP traffic:[\s\S]*?ICMP echo request.*\n.*ICMP echo reply': 'Weblogic WLS-WSAT RCE (CVE-2017-10271)',
        'Weblogic T3 Deserialize CVE-2018-2893 Exploit[\s\S]*?Malicious packet sent[\s\S]*?Captured ICMP traffic:[\s\S]*?ICMP echo request.*\n.*ICMP echo reply': 'Weblogic T3 Deserialize (CVE-2018-2893)',
        'Weblogic T3 Deserialize CVE-2016-3510 Exploit[\s\S]*?Malicious packet sent[\s\S]*?Captured ICMP traffic:[\s\S]*?ICMP echo request.*\n.*ICMP echo reply': 'Weblogic T3 Deserialize (CVE-2016-3510)',
        'Weblogic RCE CVE-2018-2894 Exploit[\s\S]*?vulnerable to CVE-2018-2894': 'Weblogic RCE (CVE-2018-2894)',
        'it\'s Vulnerable to CVE-2017-12617': 'Apache Tomcat JSP Upload Bypass RCE (CVE-2017-12617)',
        'JBoss Deserialize CVE-2015-7501 Exploit[\s\S]*?\[\+\] Command executed successfully': 'JBoss Deserialize (CVE-2015-7501)',
        'Jenkins Groovy XML RCE CVE-2016-0792 Exploit[\s\S]*?\[\+\] Command executed successfully': 'Jenkins Groovy XML RCE (CVE-2016-0792)',
        'Rails exploit CVE-2019-5418 \+ CVE-2019-5420[\s\S]*?Checking if vulnerable to CVE-2019-5418 =>\s*OK': 'Rails File Disclosure (CVE-2019-5418) + RCE (CVE-2019-5420)',
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
    'jqshell': {
        'Potential Shell Uploaded': 'Arbitrary file upload in jQuery File Upload widget (CVE-2018-9206)',
    },
    'metasploit': {
        'webdav_internal_ip[\s\S]*Found internal IP in WebDAV response (?P<m1>.*)': 'WebDAV response leaks internal IP: $1',
        'webdav_website_content[\s\S]*Found file or directory in WebDAV response (?P<m1>.*)': 'WebDAV misconfiguration - Webserver discloses its content',
        'http_put[\s\S]*File uploaded:': 'HTTP PUT enabled',
        '\[\+\] \S+:[0-9]+ (?P<m1>.*) \(200\)': 'JBoss: $1',
        '\[\+\] \S+:[0-9]+ Got authentication bypass via HTTP verb tampering': 'JBoss: Auth bypass via HTTP verb tampering (CVE-2010-0738)',
        'ibm_websphere_java_deserialize[\s\S]*?Meterpreter session [1-9] open': 'Websphere: Java Deserialization RCE (CVE-2015-7450)',
        'jenkins_java_deserialize[\s\S]*?session [1-9] open': 'Jenkins: Java Deserialization RCE (CVE-2015-8103',
        'jenkins_enum[\s\S]*?does not require authentication \(200\)': 'Jenkins: Authentication disabled',
        'joomla_comfields_sqli_rce[\s\S]*?Joomla comfields SQLi to RCE vulnerability OK': 'Joomla: Component Fields SQLi Remote Code Execution (CVE-2017-8917)',
        'struts2_code_exec_showcase[\s\S]*?session [1-9] open': 'Apache Struts2 RCE Showcase OGNL (CVE-2017-9791)',
        'Unauthenticated Jenkins console vulnerability OK': 'Jenkins: Unauthenticated Jenkins-CI script console (RCE)',
        'weblogic_deserialize[\s\S]*?session [1-9] open': 'Weblogic T3 Java Deserialize (CVE-2018-2628)',
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