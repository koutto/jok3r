=====
TODO
=====


IMPROVEMENTS / NEW FEATURES
===============================================================================

* example avec profile
* Report: print command in results 
* Update apps.json with websphere, weblogic
* Run custom command
* Session / Restore
* Change user-agent in nmap

* Create project jok3r-pocs to handle all standalone exploits/poc scripts (rce-blind, rce-standard)



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
* https://github.com/Xyntax/DirBrute/tree/master/dics

* http://pentestit.com/apache-jmeter-rmi-remote-code-execution-vulnerability-poc-cve-2018-1297/


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


Ruby ruby-2.3.8 is not installed