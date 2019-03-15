#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['http'] = {

    'changeme': {
        '\[\+\] Found Apache Tomcat( Host Manager)? default cred (?P<m1>\S*):(?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'tomcat',
        },
        '\[\+\] Found Oracle Glassfish default cred (?P<m1>\S*):(?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'glassfish',
        },
        '\[\+\] Found JBoss AS.*? default cred (?P<m1>\S*):(?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'jboss',
        },
        '\[\+\] Found (?P<m1>.*?) default cred (?P<m2>\S*):(?P<m3>\S*)': {
            'user': '$2',
            'pass': '$3',
            'type': '$1',
        },
    },
    'domiowned': {
        '^(?P<m1>\S+)\s+(?P<m2>\S+)\s+(Admin|User)\s*$': {
            'user': '$1',
            'pass': '$2',
            'type': 'domino',
        },
    },
    'metasploit': {
        # auxiliary/scanner/http/jenkins_login
        'jenkins_login[\s\S]*- Login Successful:\s*(?P<m1>\S+):(?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'jenkins',
        },
        # auxiliary/scanner/http/tomcat_enum
        '- Apache Tomcat (?P<m1>\S+) found': {
            'user': '$1',
            'type': 'tomcat',
        },
        # auxiliary/scanner/http/tomcat_mgr_login
        'tomcat_mgr_login[\s\S]*Login Successful:\s*(?P<m1>\S+):(?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'tomcat',
        },
        'jboss_vulnscan[\s\S]*Authenticated using\s*(?P<m1>\S+):(?P<m2>\S*) at ': {
            'user': '$1',
            'pass': '$2',
            'type': 'jboss',
        }
    },
    'wpscan': {
        # [i] User(s) Identified:

        # [+] user1
        #  | Detected By: Wp Json Api (Aggressive Detection)
        #  |  - https://miniwick.com/wp-json/wp/v2/users/?per_page=100&page=1
        #  | Confirmed By: Login Error Messages (Aggressive Detection)

        # [+] user2
        #  | Detected By: Rss Generator (Aggressive Detection)

        '\|\s+[0-9]+\s+\|\s+(?!None\s+)(?P<m1>\S+)\s+\|.*\|': {
            'user': '$1',
            'type': 'wordpress',
        },
    },
    'wpseku': {
        '\|\s+[0-9]+\s+\|.*\|\s+(?!None\s+)(?P<m1>\S+)\s+\|': {
            'user': '$1',
            'type': 'wordpress',
        },
    },
    'xbruteforcer': {
        'wp-login\.php\s+.*User:\s*(?<m1>\S+)\s*Pass:\s*(?<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'wordpress',
        },
        'administrator/index\.php\s+.*User:\s*(?<m1>\S+)\s*Pass:\s*(?<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'joomla',
        },
        'user/login\s+.*User:\s*(?<m1>\S+)\s*Pass:\s*(?<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'drupal',
        },
        'admin/index\.php\s+.*User:\s*(?<m1>\S+)\s*Pass:\s*(?<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'opencart',
        },
        'admin/index\.php\s+.*User:\s*(?<m1>\S+)\s*Pass:\s*(?<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'opencart',
        },
        '/admin\s+.*User:\s*(?<m1>\S+)\s*Pass:\s*(?<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'magento',
        },
    }


}