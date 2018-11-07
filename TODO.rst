=====
TODO
=====

Todo
====
* Ctrl-C better handler -> skip current, exit ?

* Improve wordlist quality:
    * passwords
    * web files/directories:
        * https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
        * https://github.com/xajkep/wordlists
        * https://www.netsparker.com/blog/web-security/svn-digger-better-lists-for-forced-browsing/
        * Administration: https://github.com/fnk0c/cangibrina/tree/master/wordlists

* Add HTML report for results:
    * Template https://www.jqueryscript.net/menu/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3.html
    * https://www.jqueryscript.net/demo/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3/
    * http://www.finalhints.com/live-search-in-html-table-using-jquery/

* Feature: Do not re-run checks already done
* info --services -> categories supported with nb of commands for each service
* argcomplete

* Doc for context, specific options (product vendor/name must be consistent with cvedetails)

* Code quality: Document code with rst docstrings:
    * https://gisellezeno.com/tutorials/sphinx-for-python-documentation.html
    * param types https://www.jetbrains.com/help/pycharm/using-docstrings-to-specify-types.html
    * return type : 
        * :return: the message id
        * :rtype: int
        """
This is a reST style.

:param param1: this is a first param
:param param2: this is a second param
:returns: this is a description of what is returned
:raises keyError: raises an exception
"""

* filter on nmap results to add
* option --disable-banner-grab for multiple targets
* option --disable-port-check
* --userlist --passlist
* Db> context-specific options management
* run command in new window/new tab
* improve info --options


Bug to fix
==========
* SmartModule HTTP: post-check method "cmseek_detect_cms"


Tools/Checks to add
===================
* Weblogic CVE-2018-2628 https://github.com/tdy218/ysoserial-cve-2018-2628
* https://github.com/chadillac/mdns_recon
* nfsshell (sudo apt-get install libreadline-dev ; make)
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

* Java-RMI -> handle case windows ping -n
* Better exploit for MS17-010 (support for more win versions, only Win7 and 2008 R2 for now)

* cve jquery
* cve ssh
* vulners-lookup
* cvedetails-lookup
* wordlists per language
* jndiat
* check https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html
* correct start module http 

Services to add
===============
* NFS
* MongoDB
* RPC
* DNS
* LDAP