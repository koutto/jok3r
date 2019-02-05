#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# Examples:
# product: Microsoft IIS httpd version: 6.0 ostype: Windows 
# product: Apache httpd version: 2.2.4 extrainfo: (Unix) DAV/2
# product: Apache httpd version: 2.0.63 extrainfo: DAV/2 hostname

WIG_REGEXP = '- Found platform {} [VERSION]'

products_match['http']['web-server'] = {
    'Adobe/Coldfusion': {
        'wappalyzer': 'Adobe ColdFusion',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service coldfusion',
            'ColdFusion Manager\s+\(version [VERSION]\)',
            'ColdFusion Manager\s+\(version Any\)',
        ],
        'wig': WIG_REGEXP.format('ColdFusion'),
    },
    'Apache/Axis2': {
        'clusterd': [
            'Matched [0-9]+ fingerprints for service axis2',
            'Axis2 Server(.+\(version [VERSION]\))?',
        ],
    },
    'Apache/Tomcat': {
        'wappalyzer': 'Apache Tomcat',
        'nmap': 'Apache Tomcat(\s+[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service tomcat',
            'Tomcat (Manager|Admin)?\s+\(version [VERSION]\)',
            'Tomcat (Manager|Admin)?\s+\(version Any\)',
        ],
        'wig': WIG_REGEXP.format('Tomcat'),
    },
    'Apache': {
        'wappalyzer': 'Apache',
        'nmap': 'Apache httpd(\s+[VERSION])?',
        'wig': WIG_REGEXP.format('Apache'),
    },
    'Domino': {
        'wappalyzer': 'Lotus Domino',
        'nmap': 'Lotus Domino(\s+(International|Go))? httpd( [VERSION])?',
        'wig': WIG_REGEXP.format('Lotus Domino'),
        'domiowned': 'Domino version:\s+[VERSION]',
    },
    'Eclipse/Jetty': {
        'wappalyzer': 'Jetty',
        'nmap': 'Jetty(\s+[VERSION])?',
    },
    'Hiawatha': {
        'wappalyzer': 'Hiawatha',
        'nmap': 'Hiawatha(\s+httpd)?(\s+[VERSION])?',
    },
    'IBM/HTTP Server': {
        'wappalyzer': 'IBM HTTP Server',
        'nmap': 'IBM(\s+ (HTTP Server|httpd))(\s+[VERSION])?',
    },
    'Jboss': {
        'wappalyzer': 'JBoss Application Server',
        'nmap': 'JBoss (service httpd|Administrator|WildFly Application Server|Enterprise Application Platform)(\s+[VERSION])?',
        # Clusterd example:
        # [2018-11-15 05:04PM] Matched 5 fingerprints for service jboss
        # [2018-11-15 05:04PM]    JBoss Web Manager (version 5.1)
        # [2018-11-15 05:04PM]    JBoss EJB Invoker Servlet (version Any)
        # [2018-11-15 05:04PM]    JBoss HTTP Headers (Unreliable) (version 5.0)
        # [2018-11-15 05:04PM]    JBoss JMX Invoker Servlet (version Any)
        # [2018-11-15 05:04PM]    JBoss RMI Interface (version Any)
        # [2018-11-15 05:04PM] Fingerprinting completed.
        # [2018-11-15 05:04PM] Loading auxiliary for 'jboss'...
        # [2018-11-15 05:04PM] Finished at 2018-11-15 05:04PM
        'clusterd': [
            'Matched [0-9]+ fingerprints for service jboss',
            # Multiline regexp
            'JBoss (JMX Console|Web Console|Web Manager|Management|JMX Invoker Servlet|EJB Invoker Servlet|RMI Interface|Status Page|HTTP Headers \(Unreliable\))\s+\(version [VERSION]\)',
            'JBoss (JMX Console|Web Console|Web Manager|Management|JMX Invoker Servlet|EJB Invoker Servlet|RMI Interface|Status Page|HTTP Headers \(Unreliable\))\s+\(version Any\)',
        ],
        'wig': WIG_REGEXP.format('jBoss'),
    },
    'Jenkins': {
        'wappalyzer': 'Jenkins',
        'nmap': 'Jenkins(\s+[VERSION])?',
    },
    'Lighttpd': {
        'wappalyzer': 'lighttpd',
        'nmap': 'lighttpd(\s+[VERSION])?',
    },
    'LiteSpeed Web Server': {
        'wappalyzer': 'LiteSpeed',
        'nmap': 'LiteSpeed httpd(\s+[VERSION])?',
    },
    'Microsoft/IIS': {
        'wappalyzer': 'IIS',
        'nmap': 'Microsoft IIS (httpd|WebDAV)(\s+[VERSION])?',
        'wig': WIG_REGEXP.format('IIS'),
    },
    'Mongoose': {
        'nmap': 'Mongoose httpd(\s+[VERSION])?',
    },
    'Monkey Http Daemon': {
        'wappalyzer': 'Monkey HTTP Server',
        'nmap': 'Monkey httpd(\s+[VERSION])?',
    },
    'Nginx': {
        'wappalyzer': 'Nginx',
        'nmap': 'nginx(\s+[VERSION])?',
        'wig': WIG_REGEXP.format('nginx'),
    },
    'Oracle/Glassfish': {
        'wappalyzer': 'GlassFish',
        'nmap': 'GlassFish(\s+(Open Source Edition|Communications Server|Administration Console|application server))?(\s+[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service glassfish',
            'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\))\s+\(version [VERSION]\)',
            'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\))\s+\(version Any\)',
        ],
    },
    'Oracle/Http Server': {
        'wappalyzer': 'Oracle HTTP Server',
        'nmap': 'Oracle HTTP Server(\s+(9iAS httpd|Powered by Apache))?(.+\(version [VERSION]\))?',
    },
    'Oracle/Weblogic Server': {
        'nmap': 'WebLogic (applications server|admin httpd|httpd|Server)(\s+[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service weblogic',
            'WebLogic Admin Console (\(https\))?\s+\(version [VERSION]\)',
            'WebLogic Admin Console (\(https\))?\s+\(version Any\)',
        ],
    },
    'Railo': {
        'clusterd': [
            'Matched [0-9]+ fingerprints for service railo',
            'Railo (Server|Web Administrator|Server Administrator|AJP)\s+\(version [VERSION]\)',
            'Railo (Server|Web Administrator|Server Administrator|AJP)\s+\(version Any\)',
        ],
    },
    'Rejetto/Http File Server': {
        'nmap': 'HttpFileServer httpd(\s+[VERSION])?',
    },
    'Thttpd': {
        'wappalyzer': 'thttpd',
        'nmap': 'thttpd(\s+[VERSION])?',
    },
    'Websphere Application Server': {
        'wappalyzer': 'IBM WebSphere (Commerce|Portal)',
        'nmap': 'WebSphere (Application Server|httpd)(\s+[VERSION])?',
    },
    'Yaws': {
        'wappalyzer': 'Yaws',
        'nmap': 'Yaws httpd(\s+[VERSION])?',
    },
    'Zeus Web Server': {
        'nmap': 'Zeus httpd(\s+Admin Server)?(\s+[VERSION])?',
    },
    'Zope': {
        'wappalyzer': 'Zope',
        'nmap': 'Zope httpd(\s+[VERSION])?',
        'wig': WIG_REGEXP.format('Zope'),
    },
}

