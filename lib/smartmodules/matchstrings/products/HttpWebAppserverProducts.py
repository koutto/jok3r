#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

WIG_REGEXP  = '- Found platform {}(\s*[VERSION])?'
WIG_REGEXP2 = '{}\s*[VERSION]\s*Platform' 

products_match['http']['web-appserver'] = {
    'Adobe/Coldfusion': {
        'wappalyzer': 'Adobe ColdFusion',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service coldfusion',
            'ColdFusion Manager\s*\(version [VERSION]\)',
            'ColdFusion Manager\s*\(version Any\)',
        ],
        'wig': [
            WIG_REGEXP.format('ColdFusion'),
            WIG_REGEXP2.format('Coldfusion'),
        ],
    },
    'Apache/Axis2': {
        'clusterd': [
            'Matched [0-9]+ fingerprints for service axis2',
            'Axis2 Server\s*\(version [VERSION]\)',
            'Axis2 Server\s*\(version Any\)',
        ],
    },
    'Apache/Tomcat': {
        'wappalyzer': 'Apache Tomcat',
        'nmap-banner': 'Apache Tomcat(\s+[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service tomcat',
            'Tomcat (Manager|Admin)?\s*\(version [VERSION]\)',
            'Tomcat (Manager|Admin)?\s*\(version Any\)',
        ],
        'wig': [
            WIG_REGEXP.format('Tomcat'),
            WIG_REGEXP2.format('Tomcat'),
        ],
    },
    'Domino': {
        'wappalyzer': 'Lotus Domino',
        'nmap-banner': 'Lotus Domino(\s*(International|Go))?\s*httpd(\s*[VERSION])?',
        'wig': [
            WIG_REGEXP.format('Lotus Domino'),
            WIG_REGEXP2.format('Lotus Domino'),
        ],
        'domiowned': 'Domino version:\s*[VERSION]',
    },
    'Eclipse/Jetty': {
        'wappalyzer': 'Jetty',
        'nmap-banner': 'Jetty(\s*[VERSION])?',
    },
    'Jboss': {
        'wappalyzer': 'JBoss Application Server',
        'nmap-banner': 'JBoss (service httpd|Administrator|WildFly Application Server|Enterprise Application Platform)(\s*[VERSION])?',
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
            'JBoss (JMX Console|Web Console|Web Manager|Management|JMX Invoker Servlet|EJB Invoker Servlet|RMI Interface|Status Page|HTTP Headers \(Unreliable\))\s*\(version [VERSION]\)',
            'JBoss (JMX Console|Web Console|Web Manager|Management|JMX Invoker Servlet|EJB Invoker Servlet|RMI Interface|Status Page|HTTP Headers \(Unreliable\))\s*\(version Any\)',
        ],
        'wig': [
            WIG_REGEXP.format('jBoss'),
            WIG_REGEXP2.format('jBoss'),
        ],
    },
    'Jenkins': {
        'wappalyzer': 'Jenkins',
        'nmap-banner': 'Jenkins(\s*[VERSION])?',
    },
    'Oracle/Glassfish': {
        'wappalyzer': 'GlassFish',
        'nmap-banner': 'GlassFish(\s*(Open Source Edition|Communications Server|Administration Console|application server))?(\s*[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service glassfish',
            'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\))\s*\(version [VERSION]\)',
            'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\))\s*\(version Any\)',
        ],
    },
    'Oracle/Weblogic Server': {
        'nmap-banner': 'WebLogic (applications server|admin httpd|httpd|Server)(\s+[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service weblogic',
            'WebLogic Admin Console (\(https\))?\s*\(version [VERSION]\)',
            'WebLogic Admin Console (\(https\))?\s*\(version Any\)',
        ],
    },
    'Websphere Application Server': {
        'wappalyzer': 'IBM WebSphere (Commerce|Portal)',
        'nmap-banner': 'WebSphere (Application Server|httpd)(\s*[VERSION])?',
    },
    'Zope': {
        'wappalyzer': 'Zope',
        'nmap-banner': 'Zope httpd(\s*[VERSION])?',
        'wig': [
            WIG_REGEXP.format('Zope'),
            WIG_REGEXP2.format('Zope'),
        ],
    },
}