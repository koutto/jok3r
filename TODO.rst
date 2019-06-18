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


-- |   Webmin File Disclosure
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2006-3392

|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  OSVDB:74721



SMARTMODULES / MATCHSTRINGS
===============================================================================
Not done yet:
* impacket smbexec/wmiexec/psexec
* whatweb

      Summary   : Script, HTML5, Drupal, PHP[7.2.3], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], X-Powered-By[PHP/7.2.3], PoweredBy[-block], UncommonHeaders[x-drupal-dynamic-cache,x-content-type-options,x-generator,x-drupal-cache], MetaGenerator[Drupal 8 (https://www.drupal.org)], Content-Language[en], Apache[2.4.25], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge]

      Summary   : PHP[5.6.40], X-Powered-By[PHP/5.6.40], JQuery, PasswordField[password], HttpOnly[89f8df32fa3e404e00d734d41437761f], MetaGenerator[Joomla! - Open Source Content Management], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], Cookies[89f8df32fa3e404e00d734d41437761f], Apache[2.4.25], HTML5, Script[application/json]

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
