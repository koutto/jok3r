#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['java-rmi'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'jexboss': {
        #'\[\*\]\s*Checking\s+(?P<m1>.*):\s*\[\s*(EXPOSED|VULNERABLE)\s*\]': 'JBoss: $1 exposed/vulnerable',
        'Captured ICMP traffic:[\s\S]*ICMP echo request.*\n.*ICMP echo reply': 'Java-RMI Deserialize RCE in Tomcat JMX (CVE-2016-3427, CVE-2016-8735)',
    },
    'jmxbf': {
        '###SUCCESS### - We got a valid connection for: :': 'JMX Authentication disabled',
    },
    'metasploit': {
        'java_rmi_server[\s\S]*session [0-9]+ opened': 'Java RMI Server Insecure Default Configuration Java Code Execution',
        'java_jmx_server[\s\S]*session [0-9]+ opened': 'Java JMX Server Insecure Configuration Java Code Execution',
    },
    'sjet': {
        'Successfully loaded MBeanSiberas': 'Java JMX Server Insecure Configuration Java Code Execution',
    },
    'ysoserial': {
        'Captured ICMP traffic:[\s\S]*ICMP echo request.*\n.*ICMP echo reply': 'Java RMI Registry Deserialization RCE',
    },

} 