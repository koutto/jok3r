#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match


products_match['http']['web-server'] = {
    'Adobe/Coldfusion': {
        'wappalyzer': 'Adobe ColdFusion',
        'clusterd': 'Matched [0-9]+ fingerprints for service coldfusion',
    },
    'Apache/Axis2': {
        'clusterd': 'Matched [0-9]+ fingerprints for service axis2',
    },
    'Apache/Tomcat': {
        'wappalyzer': 'Apache Tomcat',
        'nmap': 'Apache Tomcat(\s+[VERSION])?',
        'clusterd': 'Matched [0-9]+ fingerprints for service tomcat',
        'wig': 'Tomcat\s+[VERSION]\s+Platform',
    },
    'Apache': {
        'wappalyzer': 'Apache',
        'nmap': 'Apache httpd(\s+[VERSION])?',
        'wig': 'Apache\s+[VERSION]\s+Platform',
    },
    'Domino': {
        'wappalyzer': 'Lotus Domino',
        'nmap': 'Lotus Domino(\s+(International|Go))? httpd( [VERSION])?',
        'wig': 'Lotus Domino\s+[VERSION]\s+Platform',
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
        'clusterd': 'Matched [0-9]+ fingerprints for service jboss',
        'wig': 'jBoss\s+[VERSION]\s+Platform',
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
        'wig': 'IIS\s+[VERSION]\s+Platform',
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
        'wig': 'nginx\s+[VERSION]\s+Platform',
    },
    'Oracle/Glassfish': {
        'wappalyzer': 'GlassFish',
        'nmap': 'GlassFish(\s+(Open Source Edition|Communications Server|Administration Console|application server))?(\s+[VERSION])?',
        'clusterd': 'Matched [0-9]+ fingerprints for service glassfish',
    },
    'Oracle/Http Server': {
        'wappalyzer': 'Oracle HTTP Server',
        'nmap': 'Oracle HTTP Server(\s+(9iAS httpd|Powered by Apache))?(\s+[VERSION])?',
    },
    'Oracle/Weblogic Server': {
        'nmap': 'WebLogic (applications server|admin httpd|httpd|Server)(\s+[VERSION])?',
        'clusterd': 'Matched [0-9]+ fingerprints for service weblogic',
    },
    'Railo': {
        'clusterd': 'Matched [0-9]+ fingerprints for service railo',
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
        'wig': 'Zope\s+[VERSION]\s+Platform',
    },
}



WEB_SERVER_VERSIONS = {
    'Adobe/Coldfusion': {
        'clusterd': 'ColdFusion Manager \(version [VERSION]',
    },
    'Apache/Axis2' : {
        'clusterd': 'Axis2 Server \(version [VERSION]',
    },
    'Apache/Tomcat' : {
        'clusterd': 'Tomcat (Manager|Admin)? \(version [VERSION]',
    },
    'JBoss' : {
        'clusterd': 'JBoss (JMX Console|Web Console|Web Manager|Management|JMX Invoker Servlet|EJB Invoker Servlet|RMI Interface|Status Page|HTTP Headers \(Unreliable\)) \(version [VERSION]',
    },
    'Oracle/Glassfish' : {
        'clusterd': 'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\)) \(version [VERSION]',
    },
    'Oracle/Weblogic Server' : {
        'clusterd': 'WebLogic Admin Console (\(https\))? \(version [VERSION]',
    },
    'Railo' : {
        'clusterd': 'Railo (Server|Web Administrator|Server Administrator|AJP) \(version [VERSION]',
    }
}

