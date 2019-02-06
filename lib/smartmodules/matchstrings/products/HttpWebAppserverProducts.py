#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

products_match['http']['web-appserver'] = {
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
    'Oracle/Glassfish': {
        'wappalyzer': 'GlassFish',
        'nmap': 'GlassFish(\s+(Open Source Edition|Communications Server|Administration Console|application server))?(\s+[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service glassfish',
            'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\))\s+\(version [VERSION]\)',
            'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\))\s+\(version Any\)',
        ],
    },
    'Oracle/Weblogic Server': {
        'nmap': 'WebLogic (applications server|admin httpd|httpd|Server)(\s+[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service weblogic',
            'WebLogic Admin Console (\(https\))?\s+\(version [VERSION]\)',
            'WebLogic Admin Console (\(https\))?\s+\(version Any\)',
        ],
    },
    'Websphere Application Server': {
        'wappalyzer': 'IBM WebSphere (Commerce|Portal)',
        'nmap': 'WebSphere (Application Server|httpd)(\s+[VERSION])?',
    },
    'Zope': {
        'wappalyzer': 'Zope',
        'nmap': 'Zope httpd(\s+[VERSION])?',
        'wig': WIG_REGEXP.format('Zope'),
    },
}