=====
TODO
=====


Docker Environment
==================
* IMPORTANT: RE INSTALL odat !! 
* re-install impacket



BUG FIXES
===============================================================================

- db > service -S -> recherche par url semble pas marcher
- db > services - ip ranges selection bug





IMPROVEMENTS / NEW FEATURES
===============================================================================
* Ctrl+C -> add possibility to switch fast mode on/off

* discovery-* checks:
    - appserver-wordlist
    - cms-wordlist
    - language-wordlist (per language => lots of work to produce wordlists for each language + add generic ie HTML, XML, LOG, TXT...)
    - general-minimal-wordlist
    - general-wordlist (raft directory)

* Auth types:
    - supported auth-type => only type that support various status/lvl (can be added in cmdline)
    - can accept other values (eg creds trouvés par changeme) and can be displayed in db>creds

* Reporting HTML:
    * https://www.jqueryscript.net/demo/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3/
    * http://www.finalhints.com/live-search-in-html-table-using-jquery/
    * At the end, prompt to open in browser like in eyewitness

* Do not re-run checks already done

* Improve wordlist quality:
    * passwords
    * wordlist per language
    * wordlist per cms
    * wordlist per server
    * web files/directories:
        * https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
        * https://github.com/xajkep/wordlists
        * https://www.netsparker.com/blog/web-security/svn-digger-better-lists-for-forced-browsing/
        * Administration: https://github.com/fnk0c/cangibrina/tree/master/wordlists


[v] Checking if the website is in HTTPS ...
[v] Checking headers ...
[I] Server: nginx/1.10.3 (Ubuntu)
[L] X-Frame-Options: Not Enforced
[I] Strict-Transport-Security: Not Enforced
[I] X-Content-Security-Policy: Not Enforced
[I] X-Content-Type-Options: Not Enforced
[v] Checking Robots.txt File ...
[L] Robots.txt Found: https://miniwick.com/robots.txt
[I] CMS Detection: WordPress
[v] Checking WordPress version ...
[I] Wordpress Version: 5.1.1
[v] Core vulnerabilities for version 5.1.1
[v] Checking WordPress theme ...
[I] Wordpress Theme: focusblog
[v] Searching vulnerable theme (focusblog) from local ExploitDB repository ...
[v] Checking old WordPress config files ...
[v] Enumerating Wordpress usernames via "Feed" ...
[v] Enumerating Wordpress usernames via "Author" ...
[-] WordPress usernames identified: 
[M] Miniwick
[v] Checking if XML-RPC services are enabled ...
[M] XML-RPC services are enabled
[v] Starting XML-RPC Brute Forcing
[v] Trying Credentials: Miniwick password
[v] Trying Credentials: Miniwick admin
[v] Trying Credentials: Miniwick 123456
[v] Trying Credentials: Miniwick Password1
[v] Trying Credentials: Miniwick Miniwick
[v] Checking XML-RPC Pingback Vulnerability ...
[v] Checking XML-RPC Brute Force Vulnerability ...
[M] Website vulnerable to XML-RPC Brute Force Vulnerability
[v] Checking WordPress forgotten password ...
[v] Checking Autocomplete Off on the login page ...
[I] Autocomplete Off Not Found: https://miniwick.com/wp-login.php
[v] Checking WordPres default files...
[-] Default WordPress Files:


>>> m = regex.search('(\[v\] Trying Credentials:\s*(?P<user>\S+)\s*(?P<password>\S+)\s*\n)+', text)
>>> m.capturesdict()
{'user': ['Miniwick', 'Miniwick', 'Miniwick', 'Miniwick', 'Miniwick'], 'password': ['password', 'admin', '123456', 'Password1', 'Miniwick']}
>>> m = regex.search('WordPress[\s\S]*?(\[v\] Trying Credentials:\s*(?P<user>\S+)\s*(?P<password>\S+)\s*\n)+', text)
>>> m.capturesdict()
{'user': ['Miniwick', 'Miniwick', 'Miniwick', 'Miniwick', 'Miniwick'], 'password': ['password', 'admin', '123456', 'Password1', 'Miniwick']}
>>> m = regex.search('WoordPress[\s\S]*?(\[v\] Trying Credentials:\s*(?P<user>\S+)\s*(?P<password>\S+)\s*\n)+', text)
>>> m.capturesdict()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: 'NoneType' object has no attribute 'capturesdict'


[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:10 <========================================================================================================================> (50 / 50) 100.00% Time: 00:00:10

[i] User(s) Identified:

[+] vedam
 | Detected By: Wp Json Api (Aggressive Detection)
 |  - https://miniwick.com/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Miniwick
 | Detected By: Rss Generator (Aggressive Detection)

[+] Finished: Fri Mar 15 14:46:51 2019
[+] Requests Done: 57
[+] Cached Requests: 50
[+] Data Sent: 11.196 KB
[+] Data Received: 6.433 MB
[+] Memory used: 48.129 MB
[+] Elapsed time: 00:00:22




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
* metasploit:
    - exploit/linux/misc/jenkins_java_deserialize
    - exploit/windows/misc/ibm_websphere_java_deserialize



CHECKS CORRECTIONS
===============================================================================


* dirsearch : -t 40 --timeout= (add --timeout to dirsearch)
* add exploitations avec clusterd



CHECKS ADDING
===============================================================================


- add https://github.com/Coalfire-Research/java-deserialization-exploits (websphere rce, jenkins rce...)

- add msfmodules for different appservers.....
- RCE Tomcat CVE-2017-12617 /usr/share/exploitdb/exploits/jsp/webapps/42966.py
    WARNING: Add verify=False !
            if 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA' in con:
                print bcolors.WARNING+url+' it\'s Vulnerable to CVE-2017-12617'+bcolors.ENDC
                print bcolors.WARNING+url+"/"+checker+bcolors.ENDC
                
        else:
            print 'Not Vulnerable to CVE-2017-12617 ' 

* Weblogic CVE-2018-2628 https://github.com/tdy218/ysoserial-cve-2018-2628
* https://github.com/chadillac/mdns_recon
* nfsshell (sudo apt-get install libreadline-dev ; make)
* https://github.com/hegusung/RPCScan.git
* https://github.com/AlisamTechnology/PRESTA-modules-shell-exploit/blob/master/PRESTA-shell-exploit.pl
* https://github.com/breenmachine/JavaUnserializeExploits
* https://github.com/DanMcInerney/pentest-machine
* Sharepoint -> https://github.com/TestingPens/SPartan
* https://github.com/SecWiki/CMS-Hunter
* Better exploit for MS17-010 (support for more win versions, only Win7 and 2008 R2 for now)
* cve jquery
* cve ssh
* check https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html




SERVICES TO ADD
===============================================================================
* NFS
* MongoDB
* RPC
* DNS
* LDAP





MATCHSTRINGS TO ADD
===============================================================================

- Wordpress usernames

____ _  _ ____ ____ ____ _  _
|    |\/| [__  |___ |___ |_/  by @r3dhax0r
|___ |  | ___| |___ |___ | \_ Version 1.1.0 ForumZ


 [+]  Deep Scan Results  [+] 


 ┏━Target: wordpress.com
 ┃
 ┠── CMS: WordPress
 ┃    │
 ┃    ╰── URL: https://wordpress.org
 ┃
 ┠──[WordPress Deepscan]
 ┃    │
 ┃    ├── Usernames harvested: 1
 ┃    │    ╰── matt
 ┃    │
 ┃
 ┠── Result: /root/jok3r/toolbox/http/cmseek/Result/www.wordpress.com/cms.json
 ┃
 ┗━Scan Completed in 11.02 Seconds, using 46 Requests
