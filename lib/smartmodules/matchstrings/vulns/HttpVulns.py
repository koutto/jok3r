#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import vulns_match


vulns_match['http'] = {

    # 'tool-name': {
    #     'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
    # }

    'angularjs-csti-scanner': {
        'Found\s*.*\s*vulnerable request': {
            'name': 'AngularJS Client-Side Template Injection (CSTI)',
            'reference': 'CWE-79',
            'score': 5.3,
            'link': 'https://cwe.mitre.org/data/definitions/79.html',
        },
    },

    'clusterd': {
        # -a coldfusion --cf-hash
        'Administrative hash:': {
            'name': 'Coldfusion: Administrative hash disclosure',
            'reference': 'CVE-2010-2861',
            'score': 7.5,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2010-2861',
            'exploit_available': True,
            'exploited': True,
        },
        # -a jboss --verb-tamper
        'Vulnerable to verb tampering, attempting to deploy': {
            'name': 'JBoss: Auth bypass via HTTP verb tampering',
            'reference': 'CVE-2010-0738',
            'score': 5.0,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2010-0738',
            'exploit_available': True,
            'exploited': True,
        },
        # -a railo --rl-pw
        'Fetched encrypted password, decrypting': {
            'name': 'Railo: Password leakage via LFI',
            'exploit_available': True,
            'exploited': True,
        },
        # -a axis2 --deploy
        'deployed successfully to /axis2/services': {
            'name': 'Axis2: Web shell deployment possible',
            'exploit_available': True,
            'exploited': True,
        },
        # -a coldfusion --deploy
        'Deployed.\s*Access /userfiles/file': {
            'name': 'Coldfusion: FCKEditor exposed. Arbitrary File Upload',
            'reference': 'CVE-2009-2265',
            'score': 7.5,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2009-2265',
            'exploit_available': True,
            'exploited': True,
        },
        '-a coldfusion --deploy[\s\S]*?(deployed at|deployed to|Deployed\. \s*'
        'Access /CFIDE/ad123.cfm)': {
            'name': 'Coldfusion: Web shell deployment possible',
            'score': 10.0,
            'exploit_available': True,
            'exploited': True,
        },
        # -a glassfish --deploy
        '-a glassfish --deploy[\s\S]*?Deployed .* to': {
            'name': 'Glassfish: Web shell deployment possible',
            'score': 10.0,
            'exploit_available': True,
            'exploited': True,
        },
        # -a jboss --deploy
        '-a jboss --deploy[\s\S]*?(deployed to|Successfully deployed)': {
            'name': 'JBoss: Web shell deployment possible',
            'score': 10.0,
            'exploit_available': True,
            'exploited': True,
        },
        # -a railo --deploy
        '-a railo --deploy[\s\S]*?deployed at': {
            'name': 'Railo: Web shell deployment possible',
            'score': 10.0,
            'exploit_available': True,
            'exploited': True,
        },
        # -a tomcat --deploy
        '-a tomcat --deploy[\s\S]*?(Deployed .* to /|is already deployed)': {
            'name': 'Tomcat: Web shell deployment possible',
            'score': 10.0,
            'exploit_available': True,
            'exploited': True,
        },
        # -a weblogic --deploy
        '-a weblogic --deploy[\s\S]*?deployed at': {
            'name': 'Weblogic: Web shell deployment possible',
            'score': 10.0,
            'exploit_available': True,
            'exploited': True,
        },
    },

    'cmsmap': {
        '\[M\]\s*(?P<m1>.+)': {
            'name': '$1',
        },
    },

    'cvedetails-lookup': {
        # '^\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+1': 'CVE-$1 ($2): $3... ($4) - Exploit available',
        # '^\|\s+CVE-(?P<m1>\S+)\s+\|\s+(?P<m2>\S+)\s+\|\s+\S+\s+\|\s+(?P<m3>.*?)\s+\|\s+(?P<m4>\S+)\s+\|\s+None': 'CVE-$1 ($2): $3... ($4)',
        #'^CVE-(?P<m1>\S+?);(?P<m2>\S+?);(?P<m3>\S+?);(?P<m4>.+?);(?P<m5>\S+?);None$': 'CVE-$1 ($2): $4 ($3) - $5',
        '^CVE-(?P<m1>\S+?);(?P<m2>\S+?);(?P<m3>\S+?);(?P<m4>.+?);(?P<m5>\S+?);'
        '(?P<m6>\S+)$': {
            'name': '$4',
            'reference': 'CVE-$1',
            'score': '$2',
            'link': '$5',
            'exploit_available': '$6',
        },
    },

    'domiowned': {
        '(?P<m1>.+) does not require authentication': {
            'name': 'Domino: No authentication on $1',
            'reference': 'CVE-2011-1520',
            'score': 7.2,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2011-1520',
            'exploit_available': True,
        },
    },

    'drupwn': {
        'Drupwn>\s*exploit\s+CVE-2018-7600\s*\n[\s\S]*?\[\+\] Exploit completed. '
        'Webshell accessible at: (?P<m2>\S+)': {
            'name': 'Drupalgeddon2 RCE in CMS Drupal 7.x < 7.58 & 8.x < 8.1',
            'reference': 'CVE-2018-7600',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2018-7600',
            'exploit_available': True,
            'exploited': True,
        },
        'Drupwn>\s*exploit\s+CVE-2019-6340\s*\n[\s\S]*?\[\+\] Exploit completed. '
        'Webshell accessible at: (?P<m2>\S+)': {
            'name': 'REST RCE in CMS Drupal 8.5.x < 8.5.11 & 8.6.x < 8.6.10',
            'reference': 'CVE-2019-6340',
            'score': 8.1,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-6340',
            'exploit_available': True,
            'exploited': True,
        },        
    },

    'iis-shortname-scanner': {
        'Result: Vulnerable': {
            'name': 'IIS short filename (8.3) disclosure vulnerability',
            'link': 'https://www.exploit-db.com/exploits/19525',
            'exploit_available': True,
            'exploited': True,
        },
    },

    'exploit-weblogic-cve2017-3248': {
        '\[\+\] target \S+:\S+ is vulnerable': {
            'name': 'Weblogic RMI Registry UnicastRef Object Java Deserialization RCE',
            'reference': 'CVE-2017-3248',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2017-3248',
            'exploit_available': True,
            'exploited': True,
        },
    },

    'jok3r-pocs': {
        '\[\+\]\s*(?P<m1>.*)\s*(\[\s*(?P<m2>\S+)\s*-\s*CVSS=(?P<m3>[0-9.]*[0-9])\])?'
        ':\s*Target is EXPLOITABLE': {
            'name': '$1',
            'reference': '$2',
            'score': '$3',
            'exploit_available': True,
            'exploited': True,
        },
    },

    'joomlavs': {
        '\[!\] Title: (?P<m1>.*)\n.*Reference: (?P<m2>.*)': {
            'name': 'Joomla: $1',
            'link': '$2',
        },
    },

    'joomscan': {
        '(\[\+\+\] )?(?P<m1>(.*))\nCVE\s*:\s*(?P<m2>\S+)': {
            'name': 'Joomla: $1',
            'reference': '$2',
        },
        'cannot ensure.*\n(Title : (?P<m1>.*)\n)?Reference : (?P<m2>\S+)': {
            'name': 'Joomla (possible false positive): $1',
            'reference': '$2',
        },
        'Location.*\n(Title : (?P<m1>.*)\n)?Reference : (?P<m2>.*)': {
            'name': 'Joomla: $1',
            'reference': '$2',
        },
    },

    'jexboss': {
        '\[\*\]\s*Checking\s+(?P<m1>.*):\s*\[\s*'
        '(EXPOSED|VULNERABLE|MAYBE VULNERABLE)\s*\]': {
            'name': '$1 Vulnerable/Exposed',
            'score': 9.8,
        },
    },

    'jqshell': {
        'Potential Shell Uploaded': {
            'name': 'Arbitrary file upload in jQuery File Upload widget',
            'reference': 'CVE-2018-9206',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2018-9206',
        },
    },

    'metasploit': {
        'webdav_internal_ip[\s\S]*Found internal IP in WebDAV response (?P<m1>.*)': {
            'name': 'WebDAV response leaks internal IP: $1',
            'reference': 'CVE-2002-0422',
            'score': 2.6,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2002-0422',
            'exploit_available': True,
            'exploited': True,
        },
        'webdav_website_content[\s\S]*Found file or directory in WebDAV '
        'response (?P<m1>.*)': {
            'name': 'WebDAV misconfiguration - Webserver discloses its content',
            'exploit_available': True,
            'exploited': True,
        },
        'http_put[\s\S]*File uploaded:': {
            'name': 'HTTP PUT enabled',
            'reference': 'OSVDB-397',
            'link': 'https://vulners.com/osvdb/OSVDB:397',
            'exploit_available': True,
            'exploited': True,
        },
        '\[\+\] \S+:[0-9]+ (?P<m1>.*) \(200\)': {
            'name': 'JBoss: $1',
            'exploit_available': True,
            'exploited': True,
        },
        '\[\+\] \S+:[0-9]+ Got authentication bypass via HTTP verb tampering': {
            'name': 'JBoss: Auth bypass via HTTP verb tampering',
            'reference': 'CVE-2010-0738',
            'score': 5.0,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2010-0738',
            'exploit_available': True,
            'exploited': True,
        },
        'ibm_websphere_java_deserialize[\s\S]*?Meterpreter session [1-9] open': {
            'name': 'Websphere: Java Deserialization RCE',
            'reference': 'CVE-2015-7450',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2015-7450',
            'exploit_available': True,
            'exploited': True,
        },
        'jenkins_enum[\s\S]*?does not require authentication \(200\)': {
            'name': 'Jenkins: Authentication disabled',
            'score': 7.5,
            'exploit_available': True,
        },
        'joomla_comfields_sqli_rce[\s\S]*?Retrieved table prefix': {
            'name': 'Joomla: Component Fields SQLi Remote Code Execution',
            'reference': 'CVE-2017-8917',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2017-8917',
            'exploit_available': True,
            'exploited': True,
        },
        'struts2_code_exec_showcase[\s\S]*?session [1-9] open': {
            'name': 'Apache Struts2 RCE Showcase OGNL',
            'reference': 'CVE-2017-9791',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2017-9791',
            'exploit_available': True,
            'exploited': True,
        },
        'jenkins_command[\s\S]*?\[\+\]\s*(The server is vulnerable|'
        'Unauthenticated Jenkins console vulnerability OK)': {
            'name': 'Jenkins: Unauthenticated Jenkins-CI script console (RCE)',
            'reference': 'CVE-2015-8103',
            'score': 7.5,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2015-8103',
            'exploit_available': True,
            'exploited': True,
        },
        'wildfly_traversal[\s\S]*File saved in:': {
            'name': 'Jboss: WildFly Directory Traversal',
            'reference': 'CVE-2014-7816',
            'score': 5.0,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2014-7816',
            'exploit_available': True,
            'exploited': True,
        },
        'glassfish_traversal[\s\S]*File saved in:': {
            'name': 'Glassfish: Path Traversal',
            'reference': 'CVE-2017-1000028',
            'score': 7.5,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2017-1000028',
            'exploit_available': True,
            'exploited': True,
        },
        'adobe_xml_inject[\s\S]*(root:|\[extensions\])': {
            'name': 'Adobe Coldfusion: Adobe XML Injection file content disclosure (XXE)',
            'reference': 'CVE-2009-3960',
            'score': 4.3,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2009-3960',
            'exploit_available': True,
            'exploited': True,
        },
        'coldfusion_locale_traversal[\s\S]*\[\+\].*?FILE:': {
            'name': 'Adobe Coldfusion: Multiple directory traversal vulnerabilities in '
                    'the administrator console in Adobe ColdFusion 9.0.1 and earlier '
                    'allow remote attackers to read arbitrary files via the locale '
                    'parameter to (1) CFIDE/administrator/settings/mappings.cfm, (2) '
                    'logging/settings.cfm, (3) datasources/index.cfm, '
                    '(4) j2eepackaging/editarchive.cfm, and (5) enter.cfm in '
                    'CFIDE/administrator/.',
            'reference': 'CVE-2010-2861',
            'score': 7.5,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2010-2861',
            'exploit_available': True,
            'exploited': True,
        },
        'coldfusion_pwd_props[\s\S]*password\.properties stored in': {
            'name': 'Adobe Coldfusion: Path Traversal',
            'reference': 'CVE-2013-3336',
            'score': 5.0,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2013-3336',
            'exploit_available': True,
            'exploited': True,
        },
    },

    'nikto': {
        # Remove unrelevant vulnerabilities
        '^"\S+?","\S+?","\S+?","(?P<m1>\S+?)","\S+?",' 
        '"(?P<m2>(?!/nikto-updates).*?)",'
        '"(?P<m3>(?!The anti-clickjacking|The X-XSS-Protection|'
        'The site uses SSL and Expect-CT header)'
        '.+?)"$': {
            'name': '$3 ($2)',
            'reference': '$1',
            'location': '$2',
        },
    },
    'nmap': {
        'VULNERABLE:\s*\n\s*\|\s*(?P<m1>.+?)\s*\n\s*\|\s*State: VULNERABLE\s*\n\s*\|'
        '\s*IDs:\s*CVE:(?P<m2>\S+)': {
            'name': '$1',
            'reference': '$2',
        },
    },
    'shocker': {
        'looks vulnerable': {
            'name': 'Shellshock RCE: GNU Bash through 4.3 processes trailing strings '
                    'after function definitions in the values of environment variables, '
                    'which allows remote attackers to execute arbitrary code via a '
                    'crafted environment',
            'reference': 'CVE-2014-6271',
            'score': 9.8,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2014-6271',
            'exploit_available': True,
            'exploited': True,
        },
    },
    'struts-pwn-cve2017-9805': {
        'Status:\s+Vulnerable': {
            'name': 'Apache Struts2 REST Plugin XStream RCE: The REST Plugin in Apache '
                    'Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 '
                    'uses an XStreamHandler with an instance of XStream for '
                    'deserialization without any type filtering, which can lead to '
                    'Remote Code Execution when deserializing XML payloads.',
            'reference': 'CVE-2017-9805',
            'score': 8.1,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2017-9805',
            'exploit_available': True,
            'exploited': True,
        },
    },
    'struts-pwn-cve2018-11776': {
        'Status:\s+Vulnerable': {
            'name': 'Apache Struts2 RCE',
            'reference': 'CVE-2018-11776',
            'score': 8.1,
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2018-11776',
            'exploit_available': True,
            'exploited': True,
        },
    },
    'vulners-lookup': {
        '^(?!ID;CVSS;Title;Description;URL;Type)'
        '(?P<m1>\S+?);(?P<m2>\S+?);(?P<m3>.+?);(?P<m4>.+?);(?P<m5>.+?);.+?$': {
            'name': '$3: $4',
            'reference': '$1',
            'score': '$2',
            'link': '$5',        
        },
    },
    'vulnx': {
        '\[\?\]\s*(?P<m1>.+?)\s+VULN': {
            'name': 'Vulnerable component: $1',
            'exploit_available': True,
            'exploited': True,
        },
    },
    'wpscan': {
        #'\[!\] Title: (?P<m1>.*)': 'Wordpress: $1',
        '\[!\] Title: (?P<m1>.*)\n(\s*\|\s*.*?\n)+?\s*\|\s*References:\s*\n\s*\|\s*-\s*'
        '(?P<m2>\S+)': {
            'name': '$1',
            'link': '$2',
        },
    },

} 