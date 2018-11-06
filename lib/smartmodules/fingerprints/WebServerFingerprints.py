# -*- coding: utf-8 -*-
###
### SmartModules > Fingerprints > WebServerFingerprint
###
# List of most common web servers: https://en.wikipedia.org/wiki/Comparison_of_web_server_software

WEBSERVER_NAME_WAPPALYZER = {
	'Apache Tomcat' : 'Apache/Tomcat',
	'Apache' : 'Apache',
	'Jetty' : 'Eclipse/Jetty',
	'Hiawatha' : 'Hiawatha',
	'Lotus Domino' : 'Domino',
	'IBM HTTP Server' : 'IBM/HTTP Server',
	'JBoss Application Server' : 'JBoss',
	'JBoss Web' : 'JBoss',
	'Jenkins' : 'Jenkins',
	'lighttpd' : 'Lighttpd',
	'LiteSpeed' : 'LiteSpeed Web Server',
	'IIS' : 'Microsoft/IIS',
	'Monkey HTTP Server' : 'Monkey Http Daemon',
	'Nginx' : 'Nginx',
	'Oracle HTTP Server' : 'Oracle/Http Server',
	'GlassFish' : 'Oracle/Glassfish',
	'thttpd' : 'Thttpd',
	'IBM WebSphere (Commerce|Portal)' : 'Websphere Application Server',
	'Yaws' : 'Yaws',
	'Zope' : 'Zope',
}

WEBSERVER_NAME_VERSION_NMAP = {
	'Apache Tomcat(\s+[VERSION])?' : 'Apache/Tomcat',
	'Apache httpd(\s+[VERSION])?' : 'Apache',
	'Jetty(\s+[VERSION])?' : 'Eclipse/Jetty',
	'Hiawatha(\s+httpd)?(\s+[VERSION])?' : 'Hiawatha',
	'Lotus Domino(\s+(International|Go))? httpd( [VERSION])?' : 'Domino',
	'IBM(\s+ (HTTP Server|httpd))(\s+[VERSION])?' : 'IBM/HTTP Server',
	'JBoss service httpd(\s+[VERSION])?' : 'JBoss',
	'JBoss Administrator(\s+[VERSION])?' : 'JBoss',
	'JBoss WildFly Application Server(\s+[VERSION])?' : 'JBoss',
	'JBoss Enterprise Application Platform(\s+[VERSION])?' : 'JBoss',
	'Jenkins(\s+[VERSION])?' : 'Jenkins',
	'lighttpd(\s+[VERSION])?' : 'Lighttpd',
	'LiteSpeed httpd(\s+[VERSION])?' : 'LiteSpeed Web Server',
	'Microsoft IIS (httpd|WebDAV)(\s+[VERSION])?' : 'Microsoft/IIS',
	'Mongoose httpd(\s+[VERSION])?' : 'Mongoose',
	'Monkey httpd(\s+[VERSION])?': 'Monkey Http Daemon',
	'nginx(\s+[VERSION])?' : 'Nginx',
	'Oracle HTTP Server(\s+(9iAS httpd|Powered by Apache))?(\s+[VERSION])?' : 'Oracle/Http Server',
	'GlassFish(\s+(Open Source Edition|Communications Server|Administration Console|application server))?(\s+[VERSION])?' : 'Oracle/Glassfish',
	'WebLogic applications server(\s+[VERSION])?' : 'Oracle/Weblogic Server',
	'WebLogic (admin )?httpd(\s+[VERSION])?' : 'Oracle/Weblogic Server',
	'WebLogic Server(\s+[VERSION])?' : 'Oracle/Weblogic Server',
	'HttpFileServer httpd(\s+[VERSION])?' : 'Rejetto/Http File Server',
	'thttpd(\s+[VERSION])?' : 'Thttpd',
	'WebSphere httpd(\s+[VERSION])?' : 'Websphere Application Server',
	'WebSphere Application Server(\s+[VERSION])?' : 'Websphere Application Server',
	'Yaws httpd(\s+[VERSION])?' : 'Yaws',
	'Zeus httpd(\s+Admin Server)?(\s+[VERSION])?' : 'Zeus Web Server',
	'Zope httpd(\s+[VERSION])?' : 'Zope',
}

WEBSERVER_NAME_CLUSTERD = {
	'Matched [0-9]+ fingerprints for service axis2' : 'Apache/Axis2',
	'Matched [0-9]+ fingerprints for service coldfusion' : 'Adobe/Coldfusion',
	'Matched [0-9]+ fingerprints for service tomcat' : 'Apache/Tomcat',
	'Matched [0-9]+ fingerprints for service jboss' : 'JBoss',
	'Matched [0-9]+ fingerprints for service glassfish' : 'Oracle/Glassfish',
	'Matched [0-9]+ fingerprints for service railo' : 'Railo',
	'Matched [0-9]+ fingerprints for service weblogic' : 'Oracle/Weblogic Server',
}

WEBSERVER_VERSION_CLUSTERD = {
	'Adobe/Coldfusion': [
		'ColdFusion Manager \(version [VERSION]'
	],
	'Apache/Axis2' : [
		'Axis2 Server \(version [VERSION]',
	],
	'Apache/Tomcat' : [
		'Tomcat \(version [VERSION]',
		'Tomcat Manager \(version [VERSION]',
		'Tomcat Admin \(version [VERSION]'
	],
	'JBoss' : [
		'JBoss JMX Console \(version [VERSION]',
		'JBoss Web Console \(version [VERSION]',
		'JBoss Web Manager \(version [VERSION]',
		'JBoss Management \(version [VERSION]',
		'JBoss JMX Invoker Servlet \(version [VERSION]',
		'JBoss EJB Invoker Servlet \(version [VERSION]',
		'JBoss RMI Interface \(version [VERSION]',
		'JBoss Status Page \(version [VERSION]',
		'JBoss HTTP Headers (Unreliable) \(version [VERSION]',
	],
	'Oracle/Glassfish' : [
		'GlassFish Admin \(version [VERSION]',
		'GlassFish JMX RMI \(version [VERSION]',
		'GlassFish HTTP Headers (Unreliable) \(version [VERSION]',
	],
	'Oracle/Weblogic Server' : [
		'WebLogic Admin Console \(version [VERSION]',
		'WebLogic Admin Console (https) \(version [VERSION]',
	],
	'Railo' : [
		'Railo Server \(version [VERSION]',
		'Railo Web Administrator \(version [VERSION]',
		'Railo Server Administrator \(version [VERSION]',
		'Railo AJP \(version [VERSION]',
	] 
}

WEBSERVER_NAME_WIG {
	'Apache'
}

