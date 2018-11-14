=====
TODO
=====

Todo
====

* Ctrl-C better handler 
    * skip current, 
    * exit ? (not working, recheck), 
    * switch fast mode

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

* Add HTML report for results:
    * Template https://www.jqueryscript.net/menu/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3.html
    * https://www.jqueryscript.net/demo/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3/
    * http://www.finalhints.com/live-search-in-html-table-using-jquery/

* Feature: Do not re-run checks already done
* info --services -> categories supported with nb of commands for each service
* argcomplete

* Code quality: Document code with rst docstrings:
    * https://gisellezeno.com/tutorials/sphinx-for-python-documentation.html
    * param types https://www.jetbrains.com/help/pycharm/using-docstrings-to-specify-types.html
    * return type : 
        * :return: the message id
        * :rtype: int

* --userlist --passlist

* AttackProfiles

* Improve info --option

* info --products


Database:
---------
* Nmap import: filter on nmap results to add
* Specific options management
* Products management

* --userlist --passlist
* Db> context-specific options management



- bug cat-only, cat-exclude => order set...
- idea feature: search in results
- match nmap service name = ajp13

- new filter: on search keyword (ex: search=tomcat)

- ajp settings: change dir wordlists
tool        = ajpy
command_1   = python2.7 tomcat.py -v --port [PORT] bf -U [WORDLISTSDIR]/services/http/creds/app-servers/tomcat-usernames.txt -P [WORDLISTSDIR]/services/http/creds/app-servers/tomcat-passwords.txt
postrun     = ajpy_valid_creds


- service -S -> recherche par url semble pas marcher
- angularjs -> boolean (angularjs can be used with php,asp...)
- smartmodule -> webdav
    _http-iis-webdav-vuln: WebDAV is DISABLED


- Add option to disable check if target is reachable before running attack

            # Initialize Target and check if reachable
            target = Target(service, self.settings.services)
            service.up = target.smart_check(grab_banner_nmap=False)

    [*] Extracting targets from mission "lan_04" ...
    [*] Checking if targets are reachable...

- IMPORTANT: add option to disable reverse dns lookup in __init_with_ip and __init_with_url in target (to speed up !!)
    => default opt out (+test benchmark du temps pris pour le reverse lookup)

- MS17-010 not detected: ==> ) -> \) + LIKELY
  
        if re.search('Microsoft Windows system vulnerable to remote code execution \(MS08-067\)\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE', 
                     cmd_output, re.IGNORECASE):
            r.add_option('vuln-ms08-067', 'true')

        if re.search('Remote Code Execution vulnerability in Microsoft SMBv1 servers \(ms17-010\)\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE',
                     cmd_output, re.IGNORECASE):
            r.add_option('vuln-ms17-010', 'true')

        if re.search('SAMBA Remote Code Execution from Writable Share\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE', cmd_output, re.IGNORECASE):
            r.add_option('vuln-sambacry', 'true')


- add matching service nmap<->jok3r
      PORT     STATE    SERVICE       REASON
      21/tcp   closed   ftp           conn-refused
      22/tcp   closed   ssh           conn-refused
      23/tcp   closed   telnet        conn-refused
      80/tcp   closed   http          conn-refused
      443/tcp  closed   https         conn-refused
      445/tcp  filtered microsoft-ds  no-response   <-- add
      1433/tcp closed   ms-sql-s      conn-refused
      1434/tcp closed   ms-sql-m      conn-refused
      1521/tcp closed   oracle        conn-refused
      7001/tcp closed   afs3-callback conn-refused
      8000/tcp closed   http-alt      conn-refused
      8080/tcp closed   http-proxy    conn-refused
      8443/tcp closed   https-alt     conn-refused
- add context on os (ex for smb)
    - samba-rce-cve2015-0240 only if linux
    - os= si None , run anyway
    - os= si not None and not corresponding -> do not run

- wappalyzer implementation avec versions
- bug Command.py option_type line 311 -> type_
- odat add -v : python2.7 odat.py tnscmd -s 10.14.17.218 -p 1575 -d any --ping -v
- add postrun tnscmd_sid
- add re.IGNORECASE tns sid
- add sid detection:
[+] Data received by the database server: ''\x00 \x00\x00\x02\x00\x00\x00\x016\x00\x01\x08\x00\x7f\xff\x00\x01\x01]\x00 \r\x08\x00\x00\x00\x00\x00\x00\x00\x00\x01g\x00\x00\x06\x00\x00\x00\x00\x00(DESCRIPTION=(TMP=)(VSNNUM=153093632)(ERR=0)(ALIAS=LISTENER)(SECURITY=OFF)(VERSION=TNSLSNR for IBM/AIX RISC System/6000: Version 9.2.0.6.0 - Production)(START_DATE=10-NOV-2018 17:56:38)(SIDNUM=1)(LOGFILE=/apps/oracle/9.2.0/network/log/listener.log)(PRMFILE=/apps/oracle/adm/network/listener.ora)(TRACING=off)(UPTIME=23928489)(SNMP=OFF)(PID=7995588))\x02Q\x00\x00\x06\x00\x00\x00\x00\x00(ENDPOINT=(HANDLER=(HANDLER_MAXLOAD=0)(HANDLER_LOAD=0)(ESTABLISHED=0)(REFUSED=0)(HANDLER_ID=7A5359F37007-00C4-E053-9F32E94200C4)(PRE=any)(SESSION=NS)(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=parva7301586)(PORT=1521))))),,(SERVICE=(SERVICE_NAME=METHFRP1_DGMGRL.world)(INSTANCE=(INSTANCE_NAME=METHFRP1)(NUM=1)(INSTANCE_STATUS=UNKNOWN)(NUMREL=1))),,(SERVICE=(SERVICE_NAME=ROG2WDP0_DGMGRL.world)(INSTANCE=(INSTANCE_NAME=ROG2WDP0)(NUM=1)(INSTANCE_STATUS=UNKNOWN)(NUMREL=1))),,(SERVICE=(SERVICE_NAME=RSS0WDP1)(INSTANCE=(INSTANCE_NAME=RSS0WDP1)(NUM=1)(INSTANCE_STATUS=UNKNOWN)(NUMREL=1))),,''

- Check this case where sid=LISTENER ??

         cmd> python2.7 odat.py tnscmd -s 10.190.98.154 -p 1521 -d any --ping -v                                                                                                                               

        16:49:05 INFO -: alias list emptied
        16:49:05 INFO -: Data received thanks to the 'ping' cmd: '\x00A\x00\x00\x04\x00\x00\x00"\x00\x005(DESCRIPTION=(TMP=)(VSNNUM=0)(ERR=0)(ALIAS=LISTENER))'

        [1] (10.190.98.154:1521): Searching ALIAS on the 10.190.98.154 server, port 1521
        [+] 1 ALIAS received: ['LISTENER']. You should use this alias (more or less) as Oracle SID.

                                                                                                                                                                                                              


        [*] [SMART] Running post-check method "tnscmd_sid" ...
        [+] [SMART] New detected option: sid = LISTENER

        [?] Run command #02 ? [Y/n/t/w/q] q


- db - services - ip ranges selection bug

- ftp patator update smart:
14:04:27 patator    INFO - 502   29     0.006 | anonymous:                         |     1 | PASS command not implemented.
14:04:39 patator    INFO - 421   53     0.008 | anonymous:                         |     1 | Too many users logged in, closing control connection 
- ftp postexploit list dir

- ftp update smart, add anonymous creds when nmap detect + context req sur bruteforce:
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack HP JetDirect ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_d-w--w--w-   2 JetDirect  public         512 Feb 14  1999 PORT1 [NSE: writeable]


- jok3r-script for oracle install:

  - change url + reinstall
  wget https://github.com/koutto/jok3r-scripts/raw/master/oracle/odat-dependencies/oracle-instantclient12.2-sqlplus_12.2.0.1.0-2_amd64.deb
wget https://github.com/koutto/jok3r-scripts/raw/master/oracle/odat-dependencies/oracle-instantclient18.3-basic_18.3.0.0.0-2_amd64.deb
wget https://github.com/koutto/jok3r-scripts/raw/master/oracle/odat-dependencies/oracle-instantclient18.3-devel_18.3.0.0.0-2_amd64.deb
sudo dpkg -i oracle-instantclient18.3-basic_18.3.0.0.0-2_amd64.deb
sudo dpkg -i oracle-instantclient12.2-sqlplus_12.2.0.1.0-2_amd64.deb

- add in dockerfile:

  export ORACLE_HOME=`file /usr/lib/oracle/*/client64/ | tail -n 1 | cut -d':' -f1`
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib
  export PATH=$ORACLE_HOME/bin:$PATH
  
 - autre bug:
17:17:05 DEBUG -: Try to connect with APPLYSYSPUB/<UNKNOWN>
17:17:05 DEBUG -: Oracle connection string: APPLYSYSPUB/<UNKNOWN>@10.190.98.115:1521/LISTENER
17:17:05 DEBUG -: Error during connection with this account: `ORA-12514: TNS:listener does not currently know of service requested in connect descriptor`
17:17:05 DEBUG -: Try to connect with APPS/APPS
17:17:05 DEBUG -: Oracle connection string: APPS/APPS@10.190.98.115:1521/LISTENER
=> correction:
/bin/bash -c "export ORACLE_HOME=`file /usr/lib/oracle/*/client64/ | tail -n 1 | cut -d':' -f1`; export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib; export PATH=$ORACLE_HOME/bin:$PATH; python2.7 odat.py passwordguesser -s 10.190.98.114 -p 1521 -d SCAN3 -vv --force-retry --accounts-file accounts/accounts_multiple.txt"




- correct bugs below:
                        

  - root@kali:~/jok3r# python3 jok3r.py attack -t 10.250.69.217 -s smb

         ____.       __    ________              `Combine the best of...
        |    | ____ |  | __\_____  \______           ...open-source Hacking Tools`
        |    |/  _ \|  |/ /  _(__  <_  __ \ 
    /\__|    (  (_) )    <  /       \  | \/
    \________|\____/|__|_ \/______  /__|      v2.0
                         \/       \/     
    
              ~ Network & Web Pentest Framework ~
   [ Manage Toolbox | Automate Attacks | Chain Hacking Tools ]
   

[!] Unexpected error occured: format() takes no keyword arguments
Traceback (most recent call last):
  File "jok3r.py", line 30, in __init__
    arguments = ArgumentsParser(settings)
  File "/root/jok3r/lib/core/ArgumentsParser.py", line 43, in __init__
    if not self.check_args():
  File "/root/jok3r/lib/core/ArgumentsParser.py", line 299, in check_args
    else                           :  return self.check_args_attack()
  File "/root/jok3r/lib/core/ArgumentsParser.py", line 364, in check_args_attack
    status &= self.__check_args_attack_single_target()
  File "/root/jok3r/lib/core/ArgumentsParser.py", line 427, in __check_args_attack_single_target
    proto   = self.settings.services.get_protocol(self.args.service)))
TypeError: format() takes no keyword arguments

cmd> dirhunt https://www.correspondant-assurance.fr/bnppere                                                                                                                                           

Traceback (most recent call last):
  File "/usr/local/bin/dirhunt", line 11, in <module>
    load_entry_point('dirhunt==0.5.1', 'console_scripts', 'dirhunt')()
  File "/usr/lib/python3/dist-packages/pkg_resources/__init__.py", line 484, in load_entry_point
    return get_distribution(dist).load_entry_point(group, name)
  File "/usr/lib/python3/dist-packages/pkg_resources/__init__.py", line 2707, in load_entry_point
    return ep.load()
  File "/usr/lib/python3/dist-packages/pkg_resources/__init__.py", line 2325, in load
    return self.resolve()
  File "/usr/lib/python3/dist-packages/pkg_resources/__init__.py", line 2331, in resolve
    module = __import__(self.module_name, fromlist=['__name__'], level=0)
  File "/usr/local/lib/python3.6/dist-packages/dirhunt-0.5.1-py3.6.egg/dirhunt/management.py", line 13, in <module>
    from dirhunt.crawler import Crawler
  File "/usr/local/lib/python3.6/dist-packages/dirhunt-0.5.1-py3.6.egg/dirhunt/crawler.py", line 16, in <module>
    from dirhunt.sessions import Sessions
  File "/usr/local/lib/python3.6/dist-packages/dirhunt-0.5.1-py3.6.egg/dirhunt/sessions.py", line 5, in <module>
    from proxy_db.models import Proxy
ModuleNotFoundError: No module named 'proxy_db.models'


- ./optionsbleed -n 40 -a -u https://www.correspondant-epargne.fr/tpe 
No response , Normal ?
                                                                                                                                                                                        



Tools/Checks to add
===================
* Weblogic CVE-2018-2628 https://github.com/tdy218/ysoserial-cve-2018-2628
* https://github.com/chadillac/mdns_recon
* nfsshell (sudo apt-get install libreadline-dev ; make)
* https://github.com/hegusung/RPCScan.git
* https://www.magereport.com
* https://github.com/AlisamTechnology/PRESTA-modules-shell-exploit/blob/master/PRESTA-shell-exploit.pl
* https://github.com/breenmachine/JavaUnserializeExploits
* https://github.com/DanMcInerney/pentest-machine

* Better exploit for MS17-010 (support for more win versions, only Win7 and 2008 R2 for now)

* For all bruteforce with 'auth_status': NO_AUTH -> create command with username known 

* cve jquery
* cve ssh
* vulners-lookup
* cvedetails-lookup
* wordlists per language
* jndiat
* check https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html
* correct start module http 


* Java-RMI -> handle case windows ping -n

- add jenkins msf scripts
- add ssh cve enum
- add ssh libssh vuln

- Sharepoint -> https://github.com/TestingPens/SPartan

- tool ajpy=> add option --old-version + list applications



Services to add
===============
* NFS
* MongoDB
* RPC
* DNS
* LDAP