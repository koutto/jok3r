=====
TODO
=====

BUGS
===============================================================================
* When using --cat-only: [Check 01/total] => total is taking all checks in account
* cmd> java -jar jndiat.jar datasource -v -s 192.168.142.41 -p 7002   
	SEVERE:You must to choose a mandatory command (--sql-shell, --listen-port)  to run this module


IMPROVEMENTS / NEW FEATURES
===============================================================================
* Run custom command
* Session / Restore
* Indicate checks that need a reverse connection (IP reachable from target)

* |_weblogic-t3-info: T3 protocol in use (WebLogic version: 12.2.1.3)

* | http-vuln-cve2017-8917: 
|   VULNERABLE:
|   Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-8917
  => all nmap script http-vuln-***


SMARTMODULES / MATCHSTRINGS
===============================================================================
Not done yet:
* impacket smbexec/wmiexec/psexec
* whatweb
* nikto -> too many junk to extract important issues i think
* davscan
* wpseku 
* vbscan
* barmie
* snmpwn



TOOLS/CHECKS TO ADD
===============================================================================


* https://github.com/Coalfire-Research/java-deserialization-exploits/blob/master/OpenNMS/opennms_rce.py
* https://github.com/AlisamTechnology/PRESTA-modules-shell-exploit/blob/master/PRESTA-shell-exploit.pl
* Sharepoint -> https://github.com/TestingPens/SPartan
* check https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html
* https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2019-0227

* http://pentestit.com/apache-jmeter-rmi-remote-code-execution-vulnerability-poc-cve-2018-1297/
* magento sqli https://github.com/vulhub/vulhub/tree/master/magento/2.2-sqli https://github.com/ambionics/magento-exploits
* VulnX
* Wordpress RCE https://github.com/opsxcq/exploit-CVE-2016-10033


DOCUMENTATION
===============================================================================
* Important note: need to be reachable directly from target for exploit with reverse shell !


SERVICES TO ADD
===============================================================================
* NFS
    * nfsshell (sudo apt-get install libreadline-dev ; make)
* MongoDB
* RPC
    * https://github.com/hegusung/RPCScan.git
* DNS
* LDAP
* MDNS
    * https://github.com/chadillac/mdns_recon
* POP3
* REXEC
* RLOGIN
* RSH
* IMAP




Whatweb:
Summary   : Script, HTML5, Drupal, PHP[7.2.3], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], X-Powered-By[PHP/7.2.3], PoweredBy[-block], UncommonHeaders[x-drupal-dynamic-cache,x-content-type-options,x-generator,x-drupal-cache], MetaGenerator[Drupal 8 (https://www.drupal.org)], Content-Language[en], Apache[2.4.25], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge]

Summary   : PHP[5.6.40], X-Powered-By[PHP/5.6.40], JQuery, PasswordField[password], HttpOnly[89f8df32fa3e404e00d734d41437761f], MetaGenerator[Joomla! - Open Source Content Management], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], Cookies[89f8df32fa3e404e00d734d41437761f], Apache[2.4.25], HTML5, Script[application/json]





- Apache should not be updated here:

Detecting platform ...
- Found platform PHP 5.6.40
- Found platform Apache 2.3.10
- Found platform Apache 2.3.11
- Found platform Apache 2.3.12
- Found platform Apache 2.3.13
- Found platform Apache 2.3.14
- Found platform Apache 2.3.15
- Found platform Apache 2.3.16
- Found platform Apache 2.3.2
- Found platform Apache 2.3.3
- Found platform Apache 2.3.4
- Found platform Apache 2.3.5
- Found platform Apache 2.3.6
- Found platform Apache 2.3.7
- Found platform Apache 2.3.8
- Found platform Apache 2.3.9
- Found platform Apache 2.4.0
- Found platform Apache 2.4.1
- Found platform Apache 2.4.10
- Found platform Apache 2.4.11
- Found platform Apache 2.4.12
- Found platform Apache 2.4.2
- Found platform Apache 2.4.3
- Found platform Apache 2.4.4
- Found platform Apache 2.4.5
- Found platform Apache 2.4.6
- Found platform Apache 2.4.7
- Found platform Apache 2.4.8
- Found platform Apache 2.4.9
- Found platform Apache 2.2.11
- Found platform Apache 2.2.12
- Found platform Apache 2.2.13
- Found platform Apache 2.2.14
- Found platform Apache 2.2.15
- Found platform Apache 2.2.16
- Found platform Apache 2.2.17
- Found platform Apache 2.2.18
- Found platform Apache 2.2.19
- Found platform Apache 2.2.20
- Found platform Apache 2.2.21
- Found platform Apache 2.2.22
- Found platform Apache 2.2.23
- Found platform Apache 2.2.24
- Found platform Apache 2.2.25
- Found platform Apache 2.2.26
- Found platform Apache 2.2.27
- Found platform Apache 2.2.28
- Found platform Apache 2.2.29
- Found platform Apache 2.3.0
- Found platform Apache 2.3.1
- Found platform Apache 2.0.61
- Found platform Apache 2.0.62
- Found platform Apache 2.0.63
- Found platform Apache 2.0.64
- Found platform Apache 2.0.65
- Found platform Apache 2.2.10
- Found platform Apache 2.2.6
- Found platform Apache 2.2.7
- Found platform Apache 2.2.8
- Found platform Apache 2.2.9
Detecting interesting files ...
- Found file: /robots.txt (robots.txt index)
Detecting links ...
- Discovered 230 new resources
Detecting Javascript ...
Matching urlless fingerprints...
- Found fingerprint: PHP 5.6.40
Checking for cookies ...
- Found cookie: 89f8df32fa3e404e00d734d41437761f
- Found cookie: ae2494e9a7b78b2c1d228e34a45c18d3
Detecting OS ...
Searching for sub domains ...
Searching for tools ...
- Found tool: CMSmap (https://github.com/Dionach/CMSmap)
- Found tool: joomscan (http://sourceforge.net/projects/joomscan/)
Searching for vulnerabilities ...
Saved cache to: /root/.wig_cache/http..192.168.1.11..13080_-_1560552978.cache
___________________________________________ SITE INFO ___________________________________________
IP              Title                                                                            
Unknown         Home                                                                           
                                                                                                 
____________________________________________ VERSION ____________________________________________
Name            Versions                                                      Type               
Joomla!         3 | 3.3.1 | 3.3.1.rc | 3.3.2 | 3.3.2.rc | 3.3.3 | 3.3.4       CMS                
                3.3.5 | 3.3.6 | 3.4.0 | 3.4.0-alpha | 3.4.0-beta1                                
                3.4.0-beta2 | 3.4.0-beta3 | 3.4.0-rc | 3.4.1 | 3.4.1-rc                          
                3.4.1-rc2 | 3.4.2 | 3.4.2-rc | 3.4.3 | 3.4.4 | 3.4.4-rc                          
                3.4.4-rc2 | 3.4.5 | 3.4.6 | 3.4.7 | 3.4.8 | 3.4.8-rc | 3.5.0                     
                3.5.0-beta | 3.5.0-beta2 | 3.5.0-beta3 | 3.5.0-beta4                             
                3.5.0-beta5 | 3.5.0-rc | 3.5.0-rc2 | 3.5.0-rc3 | 3.5.0-rc4                       
                3.5.1 | 3.5.1-rc | 3.5.1-rc2 | 3.6.0 | 3.6.0-alpha                               
                3.6.0-beta1 | 3.6.0-beta2 | 3.6.0-rc | 3.6.0-rc2 | 3.6.1                         
                3.6.1-rc1 | 3.6.1-rc2 | 3.6.2 | 3.6.3-rc1                                        
Apache          2.4.25                                                        Platform           
PHP             5.6.40                                                        Platform           
                                                                                                 
__________________________________________ INTERESTING __________________________________________
URL             Note                                                          Type               
/robots.txt     robots.txt index                                              Interesting        
                                                                                                 
_____________________________________________ TOOLS _____________________________________________
Name            Link                                                          Software           
CMSmap          https://github.com/Dionach/CMSmap                             Joomla!            
joomscan        http://sourceforge.net/projects/joomscan/                     Joomla!            
                                                                                                 
_________________________________________________________________________________________________
Time: 32.9 sec  Urls: 825                                                     Fingerprints: 40401

                                                                                                                                                                                                                                              


[*] [SMART] SmartPostcheck processing to update context...
[*] [SMART] Product detected (already in db): web-cms=Joomla (version unknown)
[+] [SMART] Version detected for product web-language=PHP: 5.6.40
[*] [SMART] Product detected: web-language=PHP 5.6.40. Not updated because already in db
[*] [SMART] Product detected: web-server=Apache 2.4.25. Not updated because already in db
[+] [SMART] Version for product web-server=Apache updated: 2.4.25 -> 2.3.10





                                      


                          `-:/++++/:-.    .-:/++++/:-`                                    
                        .:ohdddmmmmdd.\  /.dddmmmmdddho:.                                
                      `:ydmmmmmmmmmmmmm\/mmmmmmmmmmmmmmdy:`                         
                     `+dmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmd+`                     
                    +dyo+++oshmmmmmmmmmmmmmmmmmmmmhso+++oyd+                    
                  -+-         .dmmmmmmmmmmmmmmmmd.         -+-                  
                 ``           `dmmmmmmmmmmmmmmmmd`           ``                 
                              `dmmmmmmmmmmmmmmmmd`                              
                              `ymmmmmmmmmmmmmmmmy`                              
                                .+dmmmmmmmmmmd+.                                
                                   /dmmmmmmd/                                   
                                    `odmmdo`                                    
                                      .hh.                                      
                                                        
                                                                   
                       ██╗ ██████╗ ██╗  ██╗██████╗ ██████╗ 
                       ██║██╔═══██╗██║ ██╔╝╚════██╗██╔══██╗
                       ██║██║   ██║█████╔╝  █████╔╝██████╔╝
                  ██   ██║██║   ██║██╔═██╗  ╚═══██╗██╔══██╗
                  ╚█████╔╝╚██████╔╝██║  ██╗██████╔╝██║  ██║  v3.0 BETA
                   ╚════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝ 
                  [ Network & Web Pentest Automation Framework ]
