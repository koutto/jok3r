
* Support tag variable for commands (eg. could be used to edit wordlist path before running tool)
* Support start in new tab

* Clean up code with objects: specificoption, targethost, targetservice

* Clean up wordlists :
	* delete useless line in wfuzz wordlists
	* Improve passwords wordlists
	* default/common credentials for services
	* organized by services

* Update README :
	* Required tools: nmap, metasploit, dig... 


* prefix titles with service name
* IMPORTANT: update -> when using multi tool, only update from multi

Repair tools :
- opendoor
- web-sorrow





* Nmap output parser :

for each open port :
    - if not detected by nmap, custom check for http/https
	- if service detected and supported by joker:
		run specific toolbox against the service (all categories)



    - ssh
    - ftp
    - telnet
    - vnc
    - mssql
    - mysql
    - postgresql
    rsh
    imap
    nntp
    pcanywhere
    pop3
    rexec
    rlogin
    smbnt
    - smtp
    - snmp
    svn
    vmauthd
    - jdwp
    ldap

    jms => JMET tool


Ideas for wordlists :
- https://github.com/x90skysn3k/brutespray/tree/master/wordlist
- https://github.com/milo2012/pentest_scripts/tree/master/default_accounts_wordlist