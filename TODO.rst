=====
TODO
=====


Docker Environment
==================
* IMPORTANT: RE INSTALL odat !! 
* re-install impacket



IMPROVEMENTS / NEW FEATURES
===============================================================================
* discovery-* checks:
    - appserver-wordlist
    - cms-wordlist
    - language-wordlist (per language => lots of work to produce wordlists for each language + add generic ie HTML, XML, LOG, TXT...)
    - general-minimal-wordlist
    - general-wordlist (raft directory)

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




CHECKS TO ADD
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
* dirsearch : -t 40 --timeout= (add --timeout to dirsearch)
* add exploitations avec clusterd
* https://github.com/hlldz/wildPwn


SERVICES TO ADD
===============================================================================
* NFS
* MongoDB
* RPC
* DNS
* LDAP



