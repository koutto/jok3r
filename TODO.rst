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
* Products SMTP (eg Exim) https://en.wikipedia.org/wiki/List_of_mail_server_software

* Web UI to view results in live (Flask ?)


SMARTMODULES / MATCHSTRINGS
===============================================================================
Not done yet:
* whatweb

      Summary   : Script, HTML5, Drupal, PHP[7.2.3], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], X-Powered-By[PHP/7.2.3], PoweredBy[-block], UncommonHeaders[x-drupal-dynamic-cache,x-content-type-options,x-generator,x-drupal-cache], MetaGenerator[Drupal 8 (https://www.drupal.org)], Content-Language[en], Apache[2.4.25], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge]

      Summary   : PHP[5.6.40], X-Powered-By[PHP/5.6.40], JQuery, PasswordField[password], HttpOnly[89f8df32fa3e404e00d734d41437761f], MetaGenerator[Joomla! - Open Source Content Management], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], Cookies[89f8df32fa3e404e00d734d41437761f], Apache[2.4.25], HTML5, Script[application/json]

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
* https://github.com/peacand/winsharecrawler
* https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt
* https://github.com/dwisiswant0/findom-xss
* https://github.com/devanshbatham/ParamSpider
* https://github.com/google/tsunami-security-scanner
* https://github.com/OWASP/Amass
* https://github.com/inc0d3/moodlescan
* https://github.com/m4ll0k/WAScan
* https://github.com/skavngr/rapidscan
* https://github.com/projectdiscovery/nuclei
* https://pypi.org/project/SpitzerSec/
* https://github.com/OJ/gobuster
* https://github.com/khalilbijjou/WAFNinja.git
* https://github.com/jas502n/CVE-2020-5902
* https://github.com/D4Vinci/CWFF

TOR MONITORING:
* https://github.com/andreyglauzer/VigilantOnion
* https://github.com/teal33t/poopak
* https://github.com/CIRCL/AIL-framework
* https://github.com/s-rah/onionscan
* https://github.com/automatingosint/osint_public
* https://github.com/trandoshan-io
* https://github.com/itsmehacker/DarkScrape/blob/master/README.md
* https://github.com/GoSecure/freshonions-torscraper
* https://github.com/DedSecInside/TorBot
* https://github.com/AshwinAmbal/DarkWeb-Crawling-Indexing/blob/master/README.md
* https://github.com/k4m4/onioff
* https://github.com/MikeMeliz/TorCrawl.py
* https://github.com/bunseokbot/darklight
* https://github.com/saidortiz/onion_osint
* https://github.com/vlall/Darksearch
* https://github.com/ntddk/onionstack
* https://github.com/mrrva/illCrawler
* https://github.com/scresh/Digamma
* https://github.com/reidjs/onionup/blob/master/README.md
* https://github.com/desyncr/onionuptime/blob/master/README.md

CVE SELECTION TO ADD
===============================================================================

F5 BIG-IP vulnerabilities:

* CVE-2020-5902
* CVE-2020-5903
* CVE-2020-5857
* CVE-2020-5876
* CVE-2020-5877
* CVE-2020-5883
* CVE-2020-5885
* CVE-2020-5881
* CVE-2020-5875


DOCUMENTATION
===============================================================================
* Important note: need to be reachable directly from target for exploit with reverse shell !


SERVICES TO ADD
===============================================================================
* NFS
    * nfsshell (sudo apt-get install libreadline-dev ; make)
* MongoDB
* DNS
* LDAP
* MDNS
    * https://github.com/chadillac/mdns_recon
* POP3
* REXEC
* RLOGIN
* RSH
* IMAP

Dorking capabilities (Google, shodan, Bing, Censys...)
#########################################################################################
# DORKS
#########################################################################################
Tools:
# darkd0rk3r, dorkme, fast-google-dorks-search,gdork,goodork3,google DB tool,googledorker,katana



rvm list
rvm use ruby-2.4
rvm gemset create ww

rvm gemset list
rvm gemset delete whatweb-test --force

rvm use ruby-2.4@ww
or
rvm use ruby-2.4
rvm gemset use ww

rvm current # show current env
ruby -v
http://masnun.com/2012/01/28/fetching-changed-files-diff-between-two-git-commits-in-python.html