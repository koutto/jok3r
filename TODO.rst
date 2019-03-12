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
- Ctrl+C -> add possibility to switch fast mode on/off

- discovery-* checks:
    - appserver-wordlist
    - cms-wordlist
    - language-wordlist (per language => lots of work to produce wordlists for each language + add generic ie HTML, XML, LOG, TXT...)
    - general-minimal-wordlist
    - general-wordlist (raft directory)

- Auth types:
    - supported auth-type => only type that support various status/lvl (can be added in cmdline)
    - can accept other values (eg creds trouvés par changeme) and can be displayed in db>creds

* Reporting HTML:
    * Template https://www.jqueryscript.net/menu/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3.html
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



https://github.com/govolution/betterdefaultpasslist


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




CHECKS CORRECTIONS
===============================================================================


- dirsearch : -t 40 --timeout= (add --timeout to dirsearch)
- add exploitations avec clusterd
- Add option --webdir-wordlist for check discovery-general-wordlist 




CHECKS ADDING
===============================================================================



- Jenkins scripts:
Attention; TARGETURI / et /jenkins/

msf auxiliary(scanner/http/jenkins_command) > show options 

Module options (auxiliary/scanner/http/jenkins_command):


msf auxiliary(scanner/http/jenkins_command) > run

[+] [2018.11.19-14:37:28] 10.2.153.123:8080     nt authority\system
[*] [2018.11.19-14:37:28] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/jenkins_command) > 
msf auxiliary(scanner/http/jenkins_command) > 
msf auxiliary(scanner/http/jenkins_command) > set TARGETURI /jenkins/
TARGETURI => /jenkins/
msf auxiliary(scanner/http/jenkins_command) > run

[-] [2018.11.19-14:37:51] 10.2.153.123:8080     This system is not running Jenkins-CI at /jenkins/
[*] [2018.11.19-14:37:51] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/jenkins_command) > set TARGETURI /
TARGETURI => /

- Jenkins deserialize

- add exploit/linux/misc/jenkins_java_deserialize (attention: os linux)
- add exploit/windows/misc/ibm_websphere_java_deserialize (os win)
- add auxiliary/scanner/http/jenkins_login
- add exploit/windows/misc/ibm_websphere_java_deserialize
- add https://github.com/Coalfire-Research/java-deserialization-exploits (websphere rce, jenkins rce...)
- add exploit/multi/http/jenkins_script_console
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
* ssh cve enul
* ssh libssh vuln
* jndiat
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
