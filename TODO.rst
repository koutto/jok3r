=====
TODO
=====


Docker Environment
==================
* IMPORTANT: RE INSTALL odat !! 
* re-install impacket



IMPROVEMENTS / NEW FEATURES
===============================================================================


* Improve wordlist quality:
    * wordlist per language
    * wordlist per cms
    * wordlist per server
    * web files/directories:
        * https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
        * https://github.com/xajkep/wordlists
        * https://www.netsparker.com/blog/web-security/svn-digger-better-lists-for-forced-browsing/
        * Administration: https://github.com/fnk0c/cangibrina/tree/master/wordlists

* print move to next target / end of target

* attack profiles
* nikto out of fastscan
* profile redteam (fast + critical)
* example avec profile

* --unscanned



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


* https://github.com/Coalfire-Research/java-deserialization-exploits/blob/master/OpenNMS/opennms_rce.py
* https://github.com/AlisamTechnology/PRESTA-modules-shell-exploit/blob/master/PRESTA-shell-exploit.pl
* Sharepoint -> https://github.com/TestingPens/SPartan
* check https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html
* https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2019-0227



DOCUMENTATION
===============================================================================
* Important note: need to be reachable directly from target for exploit with reverse shell !

sudo docker run -i -t --name jok3r-container -w /root/jok3r -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --shm-size 2g --net=host koutto/jok3r



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


