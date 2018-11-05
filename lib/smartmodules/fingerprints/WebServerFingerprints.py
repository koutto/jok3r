# -*- coding: utf-8 -*-
###
### SmartModules > Fingerprints > WebServerFingerprint
###

WEBSERVER_WAPPALYZER = {
	
}

WEBSERVER_NMAP = {
	'Apache Tomcat( [VERSION])?' : 'Apache/Tomcat',
	'Apache httpd( [VERSION])?' : 'Apache',
	'Lotus Domino( (International|Go))? httpd( [VERSION])?' : 'Domino',
	'JBoss service httpd( [VERSION])?' : 'JBoss',
	'JBoss Administrator( [VERSION])?' : 'JBoss',
	'JBoss WildFly Application Server( [VERSION])?' : 'JBoss',
	'JBoss Enterprise Application Platform( [VERSION])?' : 'JBoss',
	'Jenkins( [VERSION])?' : 'Jenkins',
	'Microsoft IIS (httpd|WebDAV)( [VERSION])?' : 'Microsoft/IIS',
	'nginx( [VERSION])?' : 'Nginx',
	'WebLogic applications server( [VERSION])?' : 'Oracle/Weblogic Server',
	'WebLogic (admin )?httpd( [VERSION])?' : 'Oracle/Weblogic Server',
	'WebLogic Server( [VERSION])?' : 'Oracle/Weblogic Server',

}