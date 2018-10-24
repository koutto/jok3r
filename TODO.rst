=====
TODO
=====

High Priority
=============
* Ctrl-C better handler -> skip current, exit ?

* Improve wordlist quality:
    * passwords
    * web files/directories:
        * https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
        * https://github.com/xajkep/wordlists
        * https://www.netsparker.com/blog/web-security/svn-digger-better-lists-for-forced-browsing/
        * Administration: https://github.com/fnk0c/cangibrina/tree/master/wordlists


Medium Priority
===============
* Feature: Do not re-run checks already done
* info --services -> categories supported with nb of commands for each service
* Code quality: enum with auto numbering (aenum?)
* info --checks-categories
* argcomplete
* Add HTML report for results:
    * Template https://www.jqueryscript.net/menu/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3.html
    * https://www.jqueryscript.net/demo/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3/


Low Priority
============
* Code quality: Document code with rst docstrings:
    * param types https://www.jetbrains.com/help/pycharm/using-docstrings-to-specify-types.html
    * return type : 
        * :return: the message id
        * :rtype: int

* filter on nmap results to add
* option --disable-banner-grab for multiple targets
* option --disable-port-check
* --userlist --passlist
* Db> add management of context-specific options
* for web targets, put title in comment
* run command in new window/new tab

Bug fixes
=========
* SmartModule HTTP: post-check method "cmseek_detect_cms"


TOOLS/CHECKS:
=============
* Weblogic CVE-2018-2628 https://github.com/tdy218/ysoserial-cve-2018-2628
* https://github.com/chadillac/mdns_recon
* nfsshell (sudo apt-get install libreadline-dev ; make)
* https://github.com/m8r0wn/enumdb mysql postexploit search in column 
* https://github.com/hegusung/RPCScan.git
* auxiliary/scanner/* wordpress ...
* https://github.com/1N3/BlackWidow

* For all bruteforce with 'auth_status': NO_AUTH -> create command with username known 


Not sure:
* Yasuo ?? https://github.com/0xsauby/yasuo (for ssh ?)
* https://www.magereport.com
* https://github.com/AlisamTechnology/PRESTA-modules-shell-exploit/blob/master/PRESTA-shell-exploit.pl
* https://github.com/breenmachine/JavaUnserializeExploits
* arachni
* https://github.com/DanMcInerney/pentest-machine

* https://github.com/vulnersCom/getsploit

* Java-RMI -> handle case windows ping -n
* Better exploit for MS17-010 (support for more win versions, only Win7 and 2008 R2 for now)

Services:
=========
* NFS