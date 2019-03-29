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



* attack profiles


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






root@kali:~/jok3r/toolbox/http/wfuzz# ./wfuzz -c -u http://31.204.93.90:8181//FUZZ/ -w "/root/jok3r/wordlists/services/http/discovery/raft-large-directories.txt" -t 30 --hc 400,404,405,406,429,500,502,503,504,000 
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://31.204.93.90:8181//FUZZ/
Total requests: 76114

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000103:  C=200    225 L     1269 W    16805 Ch    "docs"
000167:  C=302      0 L        0 W        0 Ch    "manager"
003761:  C=200    202 L      498 W    11432 Ch    ""
008497:  C=404      0 L       47 W     1016 Ch    "ClickInfo"
Unhandled exception: Invalid IPv6 URL




set THREADS 5

* test add_service
* test add_url
* __init_with_ip/url fix !