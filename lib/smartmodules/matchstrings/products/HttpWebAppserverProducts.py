#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match


WIG_REGEXP = '{}\s*[VERSION]\s*Platform' 
WIG_REGEXP2 = '- Found platform {}(\s*[VERSION])?'


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
        'banner': 'Apache Tomcat(\s+[VERSION])?',
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
    'Eclipse/Jetty': {
        'wappalyzer': 'Jetty',
        'banner': 'Jetty(\s*[VERSION])?',
    },
    'Jboss': {
        'wappalyzer': 'JBoss Application Server',
        'banner': 'JBoss (service httpd|Administrator|WildFly Application Server|Enterprise Application Platform)(\s*[VERSION])?',
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
    'Redhat/JBoss Web Server': {
        'wappalyzer': 'JBoss Web',
    },
    'Jenkins': {
        'wappalyzer': 'Jenkins',
        'banner': 'Jenkins(\s*[VERSION])?',
    },
    'Oracle/Glassfish': {
        'wappalyzer': 'GlassFish',
        'banner': 'GlassFish(\s*(Open Source Edition|Communications Server|Administration Console|application server))?(\s*[VERSION])?',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service glassfish',
            'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\))\s*\(version [VERSION]\)',
            'GlassFish (Admin|JMX RMI|HTTP Headers \(Unreliable\))\s*\(version Any\)',
        ],
    },
    'Oracle/Weblogic Server': {
        'wappalyzer': 'Weblogic Server',
        'banner': 'WebLogic (applications server|admin httpd|httpd|Server)(\s+[VERSION])?',
        'nmap': 'weblogic-t3-info: T3 protocol in use \(WebLogic version: [VERSION]\)',
        'clusterd': [
            'Matched [0-9]+ fingerprints for service weblogic',
            'WebLogic Admin Console (\(https\))?\s*\(version [VERSION]\)',
            'WebLogic Admin Console (\(https\))?\s*\(version Any\)',
        ],
    },
    'Oracle/Application Server': {
        'wappalyzer': 'Oracle Application Server',
    },
    'Phusion/Passenger': {
        'wappalyzer': 'Phusion Passenger',
    },
    'Railo': {
        'clusterd': [
            'Matched [0-9]+ fingerprints for service railo',
            'Railo (Server|Web Administrator|Server Administrator|AJP)\s*\(version [VERSION]\)',
            'Railo (Server|Web Administrator|Server Administrator|AJP)\s*\(version Any\)',
        ],
    },
    'Caucho Technology/Resin': {
        'wappalyzer': 'Resin',
    },
    'Websphere Application Server': {
        'wappalyzer': 'Websphere Application Server',
        'banner': 'WebSphere (Application Server|httpd)(\s*[VERSION])?',
    },
    'Zope': {
        'wappalyzer': 'Zope',
        'banner': 'Zope httpd(\s*[VERSION])?',
        'wig': [
            WIG_REGEXP.format('Zope'),
            WIG_REGEXP2.format('Zope'),
        ],
    },
    'Google/App Engine': {
        'wappalyzer': 'Google App Engine',
    },
    'SAP/Netweaver': {
        'wappalyzer': 'SAP',
    },
    'Winstone/Servlet Container': {
        'wappalyzer': 'Winstone Servlet Container',
    },
    'Apachefriends/XAMPP': {
        'wappalyzer': 'XAMPP',
    },
    'Imatix/Xitami': {
        'wappalyzer': 'Xitami',
    },


}