#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['http'] = {

    'changeme': {
        '\[\+\] Found Apache Tomcat( Host Manager)? default cred (?P<m1>\S*):(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'tomcat',
        },
        '\[\+\] Found Oracle Glassfish default cred (?P<m1>\S*):(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'glassfish',
        },
        '\[\+\] Found JBoss AS.*? default cred (?P<m1>\S*):(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'jboss',
        },
        '\[\+\] Found (?P<m1>.*?) default cred (?P<m2>\S*):(?P<m3>\S*)': {
            'meth': 'finditer',
            'user': '$2',
            'pass': '$3',
            'type': '$1',
        },
    },
    'clusterd': {
        # -a axis2 --ax-lfi
        '--ax-lfi[\s\S]*?Found credentials: (?P<m1>\S+):(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'axis2',
        },
        # -a tomcat --tc-ofetch
        '--tc-ofetch[\s\S]*?Found credentials:(\s*(?P<m1>\S+):(?P<m2>\S+)\s*\n)+': {
            'meth': 'search',
            'user': '$1',
            'pass': '$2',
            'type': 'tomcat',
        },
        # -a railo --deploy (default creds check) (railo does not have username)
        '-a railo --deploy[\s\S]*?Successfully authenticated with \'(?P<m1>\S+)\'': {
            'meth': 'finditer',
            'user': '',
            'pass': '$1',
            'type': 'railo',
        },
        # -a <appserver> --deploy (default creds check)
        '-a (?P<m1>\S+) --deploy[\s\S]*?Successfully authenticated with (?P<m2>\S+):(?P<m3>\S*)': {
            'meth': 'finditer',
            'user': '$2',
            'pass': '$3',
            'type': '$1',
        },
        # -a railo --wordlist --deploy (bruteforce with wordlist)(railo does not have username)
        '-a railo .*?--wordlist[\s\S]*?Brute forcing password[\s\S]*?Successful login with (?P<m1>\S+)': {
            'meth': 'finditer',
            'user': '',
            'pass': '$1',
            'type': 'railo',
        },
        # -a <appserver> --wordlist --deploy (bruteforce with wordlist)
        '-a (?P<m1>\S+) .*?--wordlist[\s\S]*?Brute forcing[\s\S]*?Successful login (?P<m2>\S+):(?P<m3>\S*)': {
            'meth': 'finditer',
            'user': '$2',
            'pass': '$3',
            'type': '$1',
        },
    },
    'cmseek': {
        '"wp_users":\s*"((?P<m1>\S+?),)+"': {
            'meth': 'search',
            'user': '$1',
            'type': 'wordpress',
        },
    },
    'cmsmap': {
        'CMS Detection:\s*WordPress\s*?\n[\s\S]*?(\[H\] Valid Credentials(!|:) (Username:)?\s*(?P<m1>\S+)\s*(Password:)?\s*(?P<m2>\S+)\s*?\n(Trying Credentials:.*\n)*)+': {
            'meth': 'search',
            'user': '$1',
            'pass': '$2',
            'type': 'wordpress',
        },
        'CMS Detection:\s*Joomla\s*?\n[\s\S]*?(\[H\] Valid Credentials(!|:) (Username:)?\s*(?P<m1>\S+)\s*(Password:)?\s*(?P<m2>\S+)\s*?\n(Trying Credentials:.*\n)*)+': {
            'meth': 'search',
            'user': '$1',
            'pass': '$2',
            'type': 'joomla',
        },
        'CMS Detection:\s*Drupal\s*?\n[\s\S]*?(\[H\] Valid Credentials(!|:) (Username:)?\s*(?P<m1>\S+)\s*(Password:)?\s*(?P<m2>\S+)\s*?\n(Trying Credentials:.*\n)*)+': {
            'meth': 'search',
            'user': '$1',
            'pass': '$2',
            'type': 'drupal',
        },
        'CMS Detection:\s*WordPress[\s\S]*?WordPress usernames identified:\s*?\n(\[M\]\s*(?P<m1>\S+)\s*?\n)+': {
            'meth': 'search',
            'user': '$1',
            'type': 'wordpress',
        },
    },
    'domiowned': {
        '(?P<m1>\S+)\s+(?P<m2>\S+)\s+(Admin|User)\s*?\n': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'domino',
        },
    },
    'hydra': {
        '\[http-get\] host: \S+\s+login:\s+(?P<m1>\S+)\s+password: (?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'htaccess',
        },
    },
    'metasploit': {
        # auxiliary/scanner/http/jenkins_login
        'jenkins_login[\s\S]*- Login Successful:\s*(?P<m1>\S+):(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'jenkins',
        },
        # auxiliary/scanner/http/tomcat_enum
        'tomcat_enum[\s\S]*- Apache Tomcat (?P<m1>\S+) found': {
            'meth': 'finditer',
            'user': '$1',
            'type': 'tomcat',
        },
        # auxiliary/scanner/http/tomcat_mgr_login
        'tomcat_mgr_login[\s\S]*Login Successful:\s*(?P<m1>\S+):(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'tomcat',
        },
        'jboss_vulnscan[\s\S]*Authenticated using\s*(?P<m1>\S+):(?P<m2>\S*) at ': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'jboss',
        }
    },
    'web-brutator': {
        'Found (?P<m1>\S+) creds: (?P<m2>\S*):(?P<m3>\S*)': {
            'meth': 'finditer',
            'user': '$2',
            'pass': '$3',
            'type': '$1',
        },
    },
    'wpscan': {
        # [i] User(s) Identified:

        # [+] user1
        #  | Detected By: Wp Json Api (Aggressive Detection)
        #  |  - https://miniwick.com/wp-json/wp/v2/users/?per_page=100&page=1
        #  | Confirmed By: Login Error Messages (Aggressive Detection)

        # [+] user2
        #  | Detected By: Rss Generator (Aggressive Detection)

        '\[i\] User\(s\) Identified:\s*?(\[\+\]\s*(?P<m1>\S+)\s*?\n(\s*\|.*(\n)+)*)+': {
            'meth': 'search',
            'user': '$1',
            'type': 'wordpress',
        },
        '\|\s+[0-9]+\s+\|\s+(?!None\s+)(?P<m1>\S+)\s+\|.*\|': { # deprecated
            'meth': 'finditer',
            'user': '$1',
            'type': 'wordpress',
        },
    },
    'wpseku': {
        '\|\s+[0-9]+\s+\|.*\|\s+(?!None\s+)(?P<m1>\S+)\s+\|': {
            'meth': 'finditer',
            'user': '$1',
            'type': 'wordpress',
        },
    },
    'xbruteforcer': {
        'wp-login\.php\s+.*User:\s*(?P<m1>\S+)\s*Pass:\s*(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'wordpress',
        },
        'administrator/index\.php\s+.*User:\s*(?P<m1>\S+)\s*Pass:\s*(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'joomla',
        },
        'user/login\s+.*User:\s*(?P<m1>\S+)\s*Pass:\s*(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'drupal',
        },
        'admin/index\.php\s+.*User:\s*(?P<m1>\S+)\s*Pass:\s*(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'opencart',
        },
        'admin/index\.php\s+.*User:\s*(?P<m1>\S+)\s*Pass:\s*(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'opencart',
        },
        '/admin\s+.*User:\s*(?P<m1>\S+)\s*Pass:\s*(?P<m2>\S*)': {
            'meth': 'finditer',
            'user': '$1',
            'pass': '$2',
            'type': 'magento',
        },
    }


}