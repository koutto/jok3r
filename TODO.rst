=====
TODO
=====


Docker Environment
==================
* IMPORTANT: RE INSTALL odat !! 
* re-install impacket



IMPROVEMENTS / NEW FEATURES
===============================================================================
* Do not re-run checks already done

* Improve wordlist quality:
    * passwords
        * https://github.com/1N3/BruteX/blob/master/wordlists/password_medium.txt
        * https://github.com/1N3/BruteX/blob/master/wordlists/password_weak.txt
    * wordlist per language
    * wordlist per cms
    * wordlist per server
    * web files/directories:
        * https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
        * https://github.com/xajkep/wordlists
        * https://www.netsparker.com/blog/web-security/svn-digger-better-lists-for-forced-browsing/
        * Administration: https://github.com/fnk0c/cangibrina/tree/master/wordlists




* Screenshoter : https://github.com/FortyNorthSecurity/EyeWitness/blob/master/modules/selenium_module.py
* In table services: screenshot_status, screenshot
* ssh-audit mastchstring






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



CHECKS TO ADD
===============================================================================


* add https://github.com/Coalfire-Research/java-deserialization-exploits (websphere rce, jenkins rce...)



* https://github.com/AlisamTechnology/PRESTA-modules-shell-exploit/blob/master/PRESTA-shell-exploit.pl
* https://github.com/breenmachine/JavaUnserializeExploits
* https://github.com/DanMcInerney/pentest-machine
* Sharepoint -> https://github.com/TestingPens/SPartan
* Better exploit for MS17-010 (support for more win versions, only Win7 and 2008 R2 for now)
* cve jquery
* check https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html
* dirsearch : -t 40 --timeout= (add --timeout to dirsearch)
* https://github.com/hlldz/wildPwn


update bruteforce - done for:
- ftp
- ssh
- telnet

* attack profiles


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



