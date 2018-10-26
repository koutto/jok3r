.. raw:: html

   <p align="center">

.. image:: ./pictures/logo.png

.. raw:: html

   <br class="title">

.. image:: https://img.shields.io/badge/python-3.6-blue.svg
    :target: https://www.python.org/downloads/release/python-366/
    :alt: Python 3.6

.. image:: https://readthedocs.org/projects/jok3r/badge/?version=latest
   :target: https://jok3r.readthedocs.io/en/latest/
   :alt: Documentation ReadTheDocs

.. image:: https://img.shields.io/docker/automated/koutto/jok3r.svg
    :target: https://hub.docker.com/r/koutto/jok3r/
    :alt: Docker Automated build

.. image:: https://img.shields.io/docker/build/koutto/jok3r.svg
    :alt: Docker Build Status

.. raw:: html

   </p>

==========================================
Jok3r - Network and Web Pentest Framework
==========================================

*Jok3r* is a Python3 CLI application which is aimed at **helping penetration testers 
for network infrastructure and web black-box security tests**. 

Its main goal is to **save time on everything that can be automated during network/web
pentest in order to enjoy more time on more interesting and challenging stuff**.

To achieve that, it **combines open-source Hacking tools to run various security checks
against all common network services.**

=============
Main features
=============
**Toolbox management**: 

* Install automatically all the hacking tools used by *Jok3r*,
* Keep the toolbox up-to-date,
* Easily add new tools.

**Attack automation**: 

* Target most common network services (including web),
* Run security checks by chaining hacking tools, following standard process (Reconaissance,
  Vulnerability scanning, Exploitation, Account bruteforce, (Basic) Post-exploitation).
* Let *Jok3r* automatically choose the checks to run according to the context and knowledge about the target,

**Mission management / Local database**: 

* Organize targets by missions in local database,
* Fully manage missions and targets (hosts/services) via interactive shell (like msfconsole db),
* Access results from security checks.
    

*Jok3r* has been built with the ambition to be easily and quickly customizable: 
Tools, security checks, supported network services... can be easily 
added/edited/removed by editing settings files with an easy-to-understand syntax.


============
Installation
============
**The recommended way to use Jok3r is inside a Docker container so you will not have 
to worry about dependencies issues and installing the various hacking tools of the toolbox.**

.. image:: https://raw.githubusercontent.com/koutto/jok3r/master/pictures/docker-logo.png

A Docker image is available on Docker Hub and automatically re-built at each update: 
https://hub.docker.com/r/koutto/jok3r/. It is initially based on official Kali
Linux Docker image (kalilinux/kali-linux-docker).

.. image:: https://images.microbadger.com/badges/image/koutto/jok3r.svg
   :target: https://microbadger.com/images/koutto/jok3r
   :alt: Docker Image size


**Pull Jok3r Docker Image:**

.. code-block:: console

    sudo docker pull koutto/jok3r

**Run fresh Docker container:**

.. code-block:: console

    sudo docker run -i -t --name jok3r-container -w /root/jok3r --net=host koutto/jok3r

**Important: --net=host option is required to share host's interface. It is needed for reverse
connections (e.g. Ping to container when testing for RCE, Get a reverse shell)**

Jok3r and its toolbox is ready-to-use !

* To re-run a stopped container:

.. code-block:: console

    sudo docker start -i jok3r-container

* To open multiple shells inside the container:

.. code-block:: console

    sudo docker exec -it jok3r-container bash

For information about building your own Docker image or installing *Jok3r* on your system
without using Docker, refer to https://jok3r.readthedocs.io/en/latest/installation.html

====================
Quick usage examples
====================

**Show all the tools in the toolbox**

.. code-block:: console

    python3 jok3r.py toolbox --show-all

**Install all the tools in the toolbox**

.. code-block:: console

    python3 jok3r.py toolbox --install-all --fast

**Update all the tools in the toolbox**

.. code-block:: console

    python3 jok3r.py toolbox --update-all --fast

**List supported services**

.. code-block:: console

    python3 jok3r.py info --services

**Show security checks for HTTP**

.. code-block:: console

    python3 jok3r.py info --checks http

**Create a new mission in local database**

.. code-block:: console

    python3 jok3r.py db

    jok3rdb[default]> mission -a MayhemProject

    [+] Mission "MayhemProject" successfully added
    [*] Selected mission is now MayhemProject

    jok3rdb[MayhemProject]> 

**Run security checks against an URL and add results to the mission**

.. code-block:: console

    python3 jok3r.py attack -t https://www.example.com/webapp/ --add MayhemProject

**Run security checks against a MSSQL service (without user-interaction) and add results to the mission**

.. code-block:: console

    python3 jok3r.py attack -t 192.168.1.42:1433 -s mssql --add MayhemProject --fast

**Import hosts/services from Nmap results into the mission scope**

.. code-block:: console

    python3 jok3r.py db

    jok3rdb[default]> mission MayhemProject

    [*] Selected mission is now MayhemProject

    jok3rdb[MayhemProject]> nmap results.xml

**Run security checks against all services in the given mission and store results in the database**

.. code-block:: console

    python3 jok3r.py attack -m MayhemProject --fast

**Run security checks against only FTP services running on ports 21/tcp and 2121/tcp from the mission**

.. code-block:: console

    python3 jok3r.py attack -m MayhemProject -f "port=21,2121;service=ftp" --fast

**Run security checks against only FTP services running on ports 2121/tcp and all HTTP services 
on 192.168.1.42 from the mission**

.. code-block:: console

    python3 jok3r.py attack -m MayhemProject -f "port=2121;service=ftp" -f "ip=192.168.1.42;service=http"


======================
Typical usage example
======================
You begin a pentest with several servers in the scope. Here is a typical example of usage of *JoK3r*:

1. You run *Nmap* scan on the servers in the scope.

2. You create a new mission (let's say "MayhemProject") in the local database:

.. code-block:: console

    python3 jok3r.py db

    jok3rdb[default]> mission -a MayhemProject

    [+] Mission "MayhemProject" successfully added
    [*] Selected mission is now MayhemProject

    jok3rdb[MayhemProject]> 

3. You import your results from *Nmap* scan in the database:

.. code-block:: console

    jok3rdb[MayhemProject]> nmap results.xml

4. You can then have a quick overview of all services and hosts in the scope, add some comments, add
   some credentials if you already have some knowledge about the targets (grey box pentest), and so on

.. code-block:: console

    jok3rdb[MayhemProject]> hosts

    [...]

    jok3rdb[MayhemProject]> services

    [...]

5. Now, you can run security checks against some targets in the scope. For example, if you 
   want to run checks against all Java-RMI services in the scope, you can run the following command:

.. code-block:: console

    python3 jok3r.py attack -m MayhemProject -f "service=java-rmi" --fast

6. You can view the results from the security checks either in live when the tools are 
   executed or later from the database using the following command:

.. code-block:: console

    jok3rdb[MayhemProject]> results


==================
Full Documentation
==================
Documentation is available at: https://jok3r.readthedocs.io/


============================================================
Supported Services & Security Checks (Updated on 24/10/2018)
============================================================

**Lots of checks remain to be implemented and services must be added !! Work in progress ...**

-  `AJP (default 8009/tcp)`_
-  `FTP (default 21/tcp)`_
-  `HTTP (default 80/tcp)`_
-  `Java-RMI (default 1099/tcp)`_
-  `JDWP (default 9000/tcp)`_
-  `MSSQL (default 1433/tcp)`_
-  `MySQL (default 3306/tcp)`_
-  `Oracle (default 1521/tcp)`_
-  `PostgreSQL (default 5432/tcp)`_
-  `RDP (default 3389/tcp)`_
-  `SMB (default 445/tcp)`_
-  `SMTP (default 25/tcp)`_
-  `SNMP (default 161/udp)`_
-  `SSH (default 22/tcp)`_
-  `Telnet (default 21/tcp)`_
-  `VNC (default 5900/tcp)`_


AJP (default 8009/tcp)
----------------------

.. code-block:: console

    +------------------------+------------+-------------------------------------------------------------------------------------------------+----------------+
    | Name                   | Category   | Description                                                                                     | Tool used      |
    +------------------------+------------+-------------------------------------------------------------------------------------------------+----------------+
    | nmap-recon             | recon      | Recon using Nmap AJP scripts                                                                    | nmap           |
    | tomcat-version         | recon      | Fingerprint Tomcat version through AJP                                                          | ajpy           |
    | vuln-lookup            | vulnscan   | Vulnerability lookup in Vulners.com (NSE scripts) and exploit-db.com (lots of false positive !) | vuln-databases |
    | default-creds-tomcat   | bruteforce | Check default credentials for Tomcat Application Manager                                        | ajpy           |
    | deploy-webshell-tomcat | exploit    | Deploy a webshell on Tomcat through AJP                                                         | ajpy           |
    +------------------------+------------+-------------------------------------------------------------------------------------------------+----------------+


FTP (default 21/tcp)
--------------------

.. code-block:: console

    +------------------+------------+-------------------------------------------------------------------------------------------------+----------------+
    | Name             | Category   | Description                                                                                     | Tool used      |
    +------------------+------------+-------------------------------------------------------------------------------------------------+----------------+
    | nmap-recon       | recon      | Recon using Nmap FTP scripts                                                                    | nmap           |
    | nmap-vuln-lookup | vulnscan   | Vulnerability lookup in Vulners.com (NSE scripts) and exploit-db.com (lots of false positive !) | vuln-databases |
    | ftpmap-scan      | vulnscan   | Identify FTP server soft/version and check for known vulns                                      | ftpmap         |
    | common-creds     | bruteforce | Check common credentials on FTP server                                                          | patator        |
    | bruteforce-creds | bruteforce | Bruteforce FTP accounts                                                                         | patator        |
    +------------------+------------+-------------------------------------------------------------------------------------------------+----------------+


HTTP (default 80/tcp)
---------------------

.. code-block:: console

    +--------------------------------------+-------------+--------------------------------------------------------------------------------------------------+--------------------------------+
    | Name                                 | Category    | Description                                                                                      | Tool used                      |
    +--------------------------------------+-------------+--------------------------------------------------------------------------------------------------+--------------------------------+
    | nmap-recon                           | recon       | Recon using Nmap HTTP scripts                                                                    | nmap                           |
    | load-balancing-detection             | recon       | HTTP load balancer detection                                                                     | halberd                        |
    | waf-detection                        | recon       | Identify and fingerprint WAF products protecting website                                         | wafw00f                        |
    | tls-probing                          | recon       | Identify the implementation in use by SSL/TLS servers (might allow server fingerprinting)        | tls-prober                     |
    | fingerprinting-multi-whatweb         | recon       | Identify CMS, blogging platforms, JS libraries, Web servers                                      | whatweb                        |
    | fingerprinting-app-server            | recon       | Fingerprint application server (JBoss, ColdFusion, Weblogic, Tomcat, Railo, Axis2, Glassfish)    | clusterd                       |
    | fingerprinting-server-domino         | recon       | Fingerprint IBM/Lotus Domino server                                                              | domiowned                      |
    | fingerprinting-cms-wig               | recon       | Identify several CMS and other administrative applications                                       | wig                            |
    | fingerprinting-cms-cmseek            | recon       | Detect CMS (130+ supported), detect version on Drupal, advanced scan on Wordpress/Joomla         | cmseek                         |
    | fingerprinting-cms-fingerprinter     | recon       | Fingerprint precisely CMS versions (based on files checksums)                                    | fingerprinter                  |
    | fingerprinting-cms-cmsexplorer       | recon       | Find plugins and themes (using bruteforce) installed in a CMS (Wordpress, Drupal, Joomla, Mambo) | cmsexplorer                    |
    | fingerprinting-drupal                | recon       | Fingerprint Drupal 7/8: users, nodes, default files, modules, themes enumeration                 | drupwn                         |
    | crawling-fast                        | recon       | Crawl website quickly, analyze interesting files/directories                                     | dirhunt                        |
    | crawling-fast2                       | recon       | Crawl website and extract URLs, files, intel & endpoints                                         | photon                         |
    | vuln-lookup                          | vulnscan    | Vulnerability lookup in Vulners.com (NSE scripts) and exploit-db.com (lots of false positive !)  | vuln-databases                 |
    | ssl-check                            | vulnscan    | Check for SSL/TLS configuration                                                                  | testssl                        |
    | vulnscan-multi-nikto                 | vulnscan    | Check for multiple web vulnerabilities/misconfigurations                                         | nikto                          |
    | default-creds-web-multi              | vulnscan    | Check for default credentials on various web interfaces                                          | changeme                       |
    | webdav-scan-davscan                  | vulnscan    | Scan HTTP WebDAV                                                                                 | davscan                        |
    | webdav-scan-msf                      | vulnscan    | Scan HTTP WebDAV                                                                                 | metasploit                     |
    | webdav-internal-ip-disclosure        | vulnscan    | Check for WebDAV internal IP disclosure                                                          | metasploit                     |
    | webdav-website-content               | vulnscan    | Detect webservers disclosing its content through WebDAV                                          | metasploit                     |
    | http-put-check                       | vulnscan    | Detect the support of dangerous HTTP PUT method                                                  | metasploit                     |
    | apache-optionsbleed-check            | vulnscan    | Test for the Optionsbleed bug in Apache httpd (CVE-2017-9798)                                    | optionsbleed                   |
    | shellshock-scan                      | vulnscan    | Detect if web server is vulnerable to Shellshock (CVE-2014-6271)                                 | shocker                        |
    | iis-shortname-scan                   | vulnscan    | Scan for IIS short filename (8.3) disclosure vulnerability                                       | iis-shortname-scanner          |
    | iis-internal-ip-disclosure           | vulnscan    | Check for IIS internal IP disclosure                                                             | metasploit                     |
    | tomcat-user-enum                     | vulnscan    | Enumerate users on Tomcat 4.1.0 - 4.1.39, 5.5.0 - 5.5.27, and 6.0.0 - 6.0.18                     | metasploit                     |
    | jboss-vulnscan-multi                 | vulnscan    | Scan JBoss application server for multiple vulnerabilities                                       | metasploit                     |
    | jboss-status-infoleak                | vulnscan    | Queries JBoss status servlet to collect sensitive information (JBoss 4.0, 4.2.2 and 4.2.3)       | metasploit                     |
    | jenkins-infoleak                     | vulnscan    | Enumerate a remote Jenkins-CI installation in an unauthenticated manner                          | metasploit                     |
    | cms-multi-vulnscan-cmsmap            | vulnscan    | Check for vulnerabilities in CMS Wordpress, Drupal, Joomla                                       | cmsmap                         |
    | wordpress-vulscan                    | vulnscan    | Scan for vulnerabilities in CMS Wordpress                                                        | wpscan                         |
    | wordpress-vulscan2                   | vulnscan    | Scan for vulnerabilities in CMS Wordpress                                                        | wpseku                         |
    | joomla-vulnscan                      | vulnscan    | Scan for vulnerabilities in CMS Joomla                                                           | joomscan                       |
    | joomla-vulnscan2                     | vulnscan    | Scan for vulnerabilities in CMS Joomla                                                           | joomlascan                     |
    | joomla-vulnscan3                     | vulnscan    | Scan for vulnerabilities in CMS Joomla                                                           | joomlavs                       |
    | drupal-vulnscan                      | vulnscan    | Scan for vulnerabilities in CMS Drupal                                                           | droopescan                     |
    | magento-vulnscan                     | vulnscan    | Check for misconfigurations in CMS Magento                                                       | magescan                       |
    | silverstripe-vulnscan                | vulnscan    | Scan for vulnerabilities in CMS Silverstripe                                                     | droopescan                     |
    | vbulletin-vulnscan                   | vulnscan    | Scan for vulnerabilities in CMS vBulletin                                                        | vbscan                         |
    | liferay-vulnscan                     | vulnscan    | Scan for vulnerabilities in CMS Liferay                                                          | liferayscan                    |
    | angularjs-csti-scan                  | vulnscan    | Scan for AngularJS Client-Side Template Injection                                                | angularjs-csti-scanner         |
    | jboss-deploy-shell                   | exploit     | Try to deploy shell on JBoss server (jmx|web|admin-console, JMXInvokerServlet)                   | jexboss                        |
    | struts2-rce-cve2017-5638             | exploit     | Exploit Apache Struts2 Jakarta Multipart parser RCE (CVE-2017-5638)                              | jexboss                        |
    | struts2-rce-cve2017-9805             | exploit     | Exploit Apache Struts2 REST Plugin XStream RCE (CVE-2017-9805)                                   | struts-pwn-cve2017-9805        |
    | struts2-rce-cve2018-11776            | exploit     | Exploit Apache Struts2 misconfiguration RCE (CVE-2018-11776)                                     | struts-pwn-cve2018-11776       |
    | tomcat-rce-cve2017-12617             | exploit     | Exploit for Apache Tomcat JSP Upload Bypass RCE (CVE-2017-12617)                                 | exploit-tomcat-cve2017-12617   |
    | jenkins-cliport-deserialize          | exploit     | Exploit Java deserialization in Jenkins CLI port                                                 | jexboss                        |
    | weblogic-t3-deserialize-cve2015-4852 | exploit     | Exploit Java deserialization in Weblogic T3(s) (CVE-2015-4852)                                   | loubia                         |
    | weblogic-t3-deserialize-cve2017-3248 | exploit     | Exploit Java deserialization in Weblogic T3(s) (CVE-2017-3248)                                   | exploit-weblogic-cve2017-3248  |
    | weblogic-t3-deserialize-cve2018-2893 | exploit     | Exploit Java deserialization in Weblogic T3(s) (CVE-2018-2893)                                   | exploit-weblogic-cve2018-2893  |
    | weblogic-wls-wsat-cve2017-10271      | exploit     | Exploit WLS-WSAT in Weblogic - CVE-2017-10271                                                    | exploit-weblogic-cve2017-10271 |
    | drupal-cve-exploit                   | exploit     | Check and exploit CVEs in CMS Drupal 7/8 (include Drupalgeddon2) (require user interaction)      | drupwn                         |
    | bruteforce-domino                    | bruteforce  | Bruteforce against IBM/Lotus Domino server                                                       | domiowned                      |
    | bruteforce-wordpress                 | bruteforce  | Bruteforce Wordpress accounts                                                                    | wpseku                         |
    | bruteforce-joomla                    | bruteforce  | Bruteforce Joomla account                                                                        | xbruteforcer                   |
    | bruteforce-drupal                    | bruteforce  | Bruteforce Drupal account                                                                        | xbruteforcer                   |
    | bruteforce-opencart                  | bruteforce  | Bruteforce Opencart account                                                                      | xbruteforcer                   |
    | bruteforce-magento                   | bruteforce  | Bruteforce Magento account                                                                       | xbruteforcer                   |
    | web-path-bruteforce-targeted         | bruteforce  | Bruteforce web paths when language is known (extensions adapted) (use raft wordlist)             | dirsearch                      |
    | web-path-bruteforce-blind            | bruteforce  | Bruteforce web paths when language is unknown (use raft wordlist)                                | wfuzz                          |
    | web-path-bruteforce-opendoor         | bruteforce  | Bruteforce web paths using OWASP OpenDoor wordlist                                               | wfuzz                          |
    | wordpress-shell-upload               | postexploit | Upload shell on Wordpress if admin credentials are known                                         | wpforce                        |
    +--------------------------------------+-------------+--------------------------------------------------------------------------------------------------+--------------------------------+


Java-RMI (default 1099/tcp)
---------------------------

.. code-block:: console

    +--------------------------------+-------------+--------------------------------------------------------------------------------------------------------+----------------+
    | Name                           | Category    | Description                                                                                            | Tool used      |
    +--------------------------------+-------------+--------------------------------------------------------------------------------------------------------+----------------+
    | nmap-recon                     | recon       | Attempt to dump all objects from Java-RMI service                                                      | nmap           |
    | rmi-enum                       | recon       | Enumerate RMI services                                                                                 | barmie         |
    | jmx-info                       | recon       | Get information about JMX and the MBean server                                                         | twiddle        |
    | vuln-lookup                    | vulnscan    | Vulnerability lookup in Vulners.com (NSE scripts) and exploit-db.com (lots of false positive !)        | vuln-databases |
    | jmx-bruteforce                 | bruteforce  | Bruteforce creds to connect to JMX registry                                                            | jmxbf          |
    | exploit-rmi-default-config     | exploit     | Exploit default config in RMI Registry to load classes from any remote URL (not working against JMX)   | metasploit     |
    | exploit-jmx-insecure-config    | exploit     | Exploit JMX insecure config. Auth disabled: should be vuln. Auth enabled: vuln if weak config          | metasploit     |
    | jmx-auth-disabled-deploy-class | exploit     | Deploy malicious MBean on JMX service with auth disabled (alternative to msf module)                   | sjet           |
    | tomcat-jmxrmi-deserialize      | exploit     | Exploit Java-RMI deserialize in Tomcat (CVE-2016-8735, CVE-2016-8735), req. JmxRemoteLifecycleListener | jexboss        |
    | rmi-deserialize-all-payloads   | exploit     | Attempt to exploit Java deserialize against Java RMI Registry with all ysoserial payloads              | ysoserial      |
    | tomcat-jmxrmi-manager-creds    | postexploit | Retrieve Manager creds on Tomcat JMX (req. auth disabled or creds known on JMX)                        | jmxploit       |
    +--------------------------------+-------------+--------------------------------------------------------------------------------------------------------+----------------+


JDWP (default 9000/tcp)
-----------------------

.. code-block:: console

    +------------+----------+-----------------------------------------------------+-----------------+
    | Name       | Category | Description                                         | Tool used       |
    +------------+----------+-----------------------------------------------------+-----------------+
    | nmap-recon | recon    | Recon using Nmap JDWP scripts                       | nmap            |
    | jdwp-rce   | exploit  | Gain RCE on JDWP service (show OS/Java info as PoC) | jdwp-shellifier |
    +------------+----------+-----------------------------------------------------+-----------------+


MSSQL (default 1433/tcp)
------------------------

.. code-block:: console

    +-----------------------+-------------+--------------------------------------------------------------------------------------------------------------+-----------+
    | Name                  | Category    | Description                                                                                                  | Tool used |
    +-----------------------+-------------+--------------------------------------------------------------------------------------------------------------+-----------+
    | nmap-recon            | recon       | Recon using Nmap MSSQL scripts                                                                               | nmap      |
    | mssqlinfo             | recon       | Get technical information about a remote MSSQL server (use TDS protocol and SQL browser Server)              | msdat     |
    | common-creds          | bruteforce  | Check common/default credentials on MSSQL server                                                             | msdat     |
    | bruteforce-sa-account | bruteforce  | Bruteforce MSSQL "sa" account                                                                                | msdat     |
    | audit-mssql-postauth  | postexploit | Check permissive privileges, methods allowing command execution, weak accounts after authenticating on MSSQL | msdat     |
    +-----------------------+-------------+--------------------------------------------------------------------------------------------------------------+-----------+


MySQL (default 3306/tcp)
------------------------

.. code-block:: console

    +----------------------------------+-------------+-------------------------------------------------------------------------+---------------+
    | Name                             | Category    | Description                                                             | Tool used     |
    +----------------------------------+-------------+-------------------------------------------------------------------------+---------------+
    | nmap-recon                       | recon       | Recon using Nmap MySQL scripts                                          | nmap          |
    | mysql-auth-bypass-cve2012-2122   | exploit     | Exploit password bypass vulnerability in MySQL - CVE-2012-2122          | metasploit    |
    | default-creds                    | bruteforce  | Check default credentials on MySQL server                               | patator       |
    | mysql-hashdump                   | postexploit | Retrieve usernames and password hashes from MySQL database (req. creds) | metasploit    |
    | mysql-interesting-tables-columns | postexploit | Search for interesting tables and columns in database                   | jok3r-scripts |
    +----------------------------------+-------------+-------------------------------------------------------------------------+---------------+


Oracle (default 1521/tcp)
-------------------------

.. code-block:: console

    +--------------------------+-------------+--------------------------------------------------------------------------------------------------------------+-----------+
    | Name                     | Category    | Description                                                                                                  | Tool used |
    +--------------------------+-------------+--------------------------------------------------------------------------------------------------------------+-----------+
    | tnscmd                   | recon       | Connect to TNS Listener and issue commands Ping, Status, Version                                             | odat      |
    | tnspoisoning             | vulnscan    | Test if TNS Listener is vulnerable to TNS Poisoning (CVE-2012-1675)                                          | odat      |
    | common-creds             | bruteforce  | Check common/default credentials on Oracle server                                                            | odat      |
    | bruteforce-creds         | bruteforce  | Bruteforce Oracle accounts (might block some accounts !)                                                     | odat      |
    | audit-oracle-postauth    | postexploit | Check for privesc vectors, config leading to command execution, weak accounts after authenticating on Oracle | odat      |
    | search-columns-passwords | postexploit | Search for columns storing passwords in the database                                                         | odat      |
    +--------------------------+-------------+--------------------------------------------------------------------------------------------------------------+-----------+



PostgreSQL (default 5432/tcp)
-----------------------------

.. code-block:: console

    +---------------+------------+------------------------------------------------+-----------+
    | Name          | Category   | Description                                    | Tool used |
    +---------------+------------+------------------------------------------------+-----------+
    | default-creds | bruteforce | Check default credentials on PostgreSQL server | patator   |
    +---------------+------------+------------------------------------------------+-----------+


RDP (default 3389/tcp)
----------------------

.. code-block:: console

    +----------+----------+-----------------------------------------------------------------------+------------+
    | Name     | Category | Description                                                           | Tool used  |
    +----------+----------+-----------------------------------------------------------------------+------------+
    | ms12-020 | vulnscan | Check for MS12-020 RCE vulnerability (any Windows before 13 Mar 2012) | metasploit |
    +---------+----------+-----------------------------------------------------------------------+------------+


SMB (default 445/tcp)
---------------------

.. code-block:: console

    +-----------------------------------+-------------+-------------------------------------------------------------------------------+------------+
    | Name                              | Category    | Description                                                                   | Tool used  |
    +-----------------------------------+-------------+-------------------------------------------------------------------------------+------------+
    | nmap-recon                        | recon       | Recon using Nmap SMB scripts                                                  | nmap       |
    | anonymous-enum-smb                | recon       | Attempt to perform enum (users, shares...) without account                    | nullinux   |
    | nmap-vulnscan                     | vulnscan    | Check for vulns in SMB (MS17-010, MS10-061, MS10-054, MS08-067...) using Nmap | nmap       |
    | detect-ms17-010                   | vulnscan    | Detect MS17-010 SMB RCE                                                       | metasploit |
    | samba-rce-cve2015-0240            | vulnscan    | Detect RCE vuln (CVE-2015-0240) in Samba 3.5.x and 3.6.X                      | metasploit |
    | exploit-rce-ms08-067              | exploit     | Exploit for RCE vuln MS08-067 on SMB                                          | metasploit |
    | exploit-rce-ms17-010-eternalblue  | exploit     | Exploit for RCE vuln MS17-010 EternalBlue on SMB                              | metasploit |
    | exploit-sambacry-rce-cve2017-7494 | exploit     | Exploit for SambaCry RCE on Samba <= 4.5.9 (CVE-2017-7494)                    | metasploit |
    | auth-enum-smb                     | postexploit | Authenticated enumeration (users, groups, shares) on SMB                      | nullinux   |
    | auth-shares-perm                  | postexploit | Get R/W permissions on SMB shares                                             | smbmap     |
    | smb-exec                          | postexploit | Attempt to get a remote shell (psexec-like, requires Administrator creds)     | impacket   |
    +-----------------------------------+-------------+-------------------------------------------------------------------------------+------------+


SMTP (default 25/tcp)
---------------------

.. code-block:: console

    +----------------+----------+--------------------------------------------------------------------------------------------+----------------+
    | Name           | Category | Description                                                                                | Tool used      |
    +----------------+----------+--------------------------------------------------------------------------------------------+----------------+
    | smtp-cve       | vulnscan | Scan for vulnerabilities (CVE-2010-4344, CVE-2011-1720, CVE-2011-1764, open-relay) on SMTP | nmap           |
    | smtp-user-enum | vulnscan | Attempt to perform user enumeration via SMTP commands EXPN, VRFY and RCPT TO               | smtp-user-enum |
    +----------------+----------+--------------------------------------------------------------------------------------------+----------------+


SNMP (default 161/udp)
----------------------

.. code-block:: console

    +--------------------------+-------------+---------------------------------------------------------------------+------------+
    | Name                     | Category    | Description                                                         | Tool used  |
    +--------------------------+-------------+---------------------------------------------------------------------+------------+
    | common-community-strings | bruteforce  | Check common community strings on SNMP server                       | metasploit |
    | snmpv3-bruteforce-creds  | bruteforce  | Bruteforce SNMPv3 credentials                                       | snmpwn     |
    | enumerate-info           | postexploit | Enumerate information provided by SNMP (and check for write access) | snmp-check |
    +--------------------------+-------------+---------------------------------------------------------------------+------------+


SSH (default 22/tcp)
--------------------

.. code-block:: console

    +--------------------------------+------------+--------------------------------------------------------------------------------------------+-----------+
    | Name                           | Category   | Description                                                                                | Tool used |
    +--------------------------------+------------+--------------------------------------------------------------------------------------------+-----------+
    | vulns-algos-scan               | vulnscan   | Scan supported algorithms and security info on SSH server                                  | ssh-audit |
    | user-enumeration-timing-attack | exploit    | Try to perform OpenSSH (versions <= 7.2 and >= 5.*) user enumeration timing attack OpenSSH | osueta    |
    | default-ssh-key                | bruteforce | Try to authenticate on SSH server using known SSH keys                                     | changeme  |
    | default-creds                  | bruteforce | Check default credentials on SSH                                                           | patator   |
    +--------------------------------+------------+--------------------------------------------------------------------------------------------+-----------+


Telnet (default 21/tcp)
-----------------------

.. code-block:: console

    +-------------------------+------------+----------------------------------------------------------------------------------+-----------+
    | Name                    | Category   | Description                                                                      | Tool used |
    +-------------------------+------------+----------------------------------------------------------------------------------+-----------+
    | nmap-recon              | recon      | Recon using Nmap Telnet scripts                                                  | nmap      |
    | default-creds           | bruteforce | Check default credentials on Telnet (dictionary from https://cirt.net/passwords) | patator   |
    | bruteforce-root-account | bruteforce | Bruteforce "root" account on Telnet                                              | patator   |
    +-------------------------+------------+----------------------------------------------------------------------------------+-----------+


VNC (default 5900/tcp)
----------------------

.. code-block:: console

    +-----------------+------------+-------------------------------------------------------------------------------------------------+----------------+
    | Name            | Category   | Description                                                                                     | Tool used      |
    +-----------------+------------+-------------------------------------------------------------------------------------------------+----------------+
    | nmap-recon      | recon      | Recon using Nmap VNC scripts                                                                    | nmap           |
    | vuln-lookup     | vulnscan   | Vulnerability lookup in Vulners.com (NSE scripts) and exploit-db.com (lots of false positive !) | vuln-databases |
    | bruteforce-pass | bruteforce | Bruteforce VNC password                                                                         | patator        |
    +-----------------+------------+-------------------------------------------------------------------------------------------------+----------------+
