.. _command-db:

============
Command `db`
============

The command `db` spawns an interactive shell giving access to the *Jok3r*'s local database.
**The local database stores the missions, targets info & attacks results.** It is very 
similar to the database that can be used in *Metasploit*.

The goal is to allow the pentester to create a **new mission** at the beginning of a
pentest, and to fill it with the targets (i.e. network services/URLs) that are in scope.
Most of the time, he will just **import Nmap results** from scans he has previously done,
but he can also add some targets manually by using the shell. He will be able to
**visualize and organize target information (ip, hotsname, port, banner...)**.

After running some security checks against targets in the mission, **results from the tools
- and potentially credentials that might be found - are stored** in the database and can be 
viewed from the shell. 


Here are the supported commands in the *jok3rdb* interactive shell:

.. code-block:: console

    jok3rdb[default]> help

    Documented commands (type help <topic>):

    Attacks results
    ================================================================================
    results             Attacks results

    Import
    ================================================================================
    nmap                Import Nmap results

    Missions data
    ================================================================================
    creds               Credentials in the current mission scope
    hosts               Hosts in the current mission scope
    mission             Missions management
    services            Services in the current mission scope

    Other
    ================================================================================
    alias               Define or display aliases
    help                Display this help message
    history             View, run, edit, and save previously entered commands.
    quit                Exits this application.
    set                 Sets a settable parameter or shows current settings of parameters.
    shell               Execute a command as if at the OS prompt.
    unalias             Unsets aliases


Command `mission`
=================
This command allows to create a new mission, rename or delete an existing one.
It also allow to change the current mission (the mission named *default* is selected by
default).

Here are the supported options:

.. code-block:: console

    jok3rdb[default]> mission -h
    usage: mission [-h] [-a <name>] [-c <name> <comment>] [-d <name>] [-D]
                   [-r <old> <new>] [-S <string>]
                   [<name>]

    Manage missions

    positional arguments:
      <name>                          Switch mission

    optional arguments:
      -h, --help                      show this help message and exit
      -a, --add <name>                Add mission
      -c, --comment <name> <comment>  Change the comment of a mission
      -d, --del <name>                Delete mission
      -D, --reset                     Delete all missions
      -r, --rename <old> <new>        Rename mission
      -S, --search <string>           Search string to filter by

When creating a new mission, the following command must be issued:

.. code-block:: console

    jok3rdb[default]> mission -a missionname

    [+] Mission "missionname" successfully added
    [*] Selected mission is now missionname

    jok3rdb[missionname]> 

The newly created mission is automatically selected as the new current mission.

Command `hosts`
===============
This command allows to view and to manage hosts in the current mission.

.. code-block:: console

    jok3rdb[default]> hosts -h
    usage: hosts [-h] [-c <comment> | -d] [-o <column>] [-S <string>]
                 [<addr1> <addr2> ... [<addr1> <addr2> ... ...]]

    Hosts in the current mission scope

    optional arguments:
      -h, --help               show this help message and exit

    Manage hosts:
      -c, --comment <comment>  Change the comment of selected host(s)
      -d, --del                Delete selected host(s) (instead of displaying)

    Filter hosts:
      -o, --order <column>     Order rows by specified column
      -S, --search <string>    Search string to filter by
      <addr1> <addr2> ...      IPs/CIDR ranges/hostnames to select



Command `services`
==================
This command allows to view and to manage all services in the current mission. Running 
this command without any option will display all services added into the current mission.

For better readability, there are a lot of supported filtering options in order to select 
only a subset of services to display. 

Those filtering options can also be used to add special comments, usernames, credentials 
(couples username+password) manually to one particular service or a subset of services.

.. code-block:: console

    jok3rdb[default]> services -h
    usage: services [-h]
                    [-a <host> <port> <service> | -u <url> | -d | -c <comment> | --https]
                    [--addcred <user> <pass> | --addcred-http <user> <pass> <auth-type> | --adduser <user> | --adduser-http <user> <auth-type>]
                    [-H <hostname1,hostname2...>] [-I <ip1,ip2...>]
                    [-p <port1,port2...>] [-r <protocol>] [-U] [-o <column>]
                    [-S <string>]
                    [<name1> <name2> ... [<name1> <name2> ... ...]]

    Services in the current mission scope

    optional arguments:
      -h, --help                                show this help message and exit

    Manage services:
      -a, --add <host> <port> <service>         Add a new service
      -u, --url <url>                           Add a new URL
      -d, --del                                 Delete selected service(s) (instead of displaying)
      -c, --comment <comment>                   Change the comment of selected service(s)
      --https                                   Switch between HTTPS and HTTP protocol for URL of selected service(s)

    Manage services credentials:
      --addcred <user> <pass>                   Add new credentials (username+password) for selected service(s)
      --addcred-http <user> <pass> <auth-type>  Add new credentials (username+password) for the specified authentication type on selected HTTP service(s)
      --adduser <user>                          Add new username (password unknown) for selected service(s)
      --adduser-http <user> <auth-type>         Add new username (password unknown) for the specified authentication type on selected HTTP service(s)

    Filter services:
      -H, --hostname <hostname1,hostname2...>   Search for a list of hostnames (comma-separated)
      -I, --ip <ip1,ip2...>                     Search for a list of IPs (single IP/CIDR range comma-separated)
      -p, --port <port1,port2...>               Search for a list of ports (single/range comma-separated)
      -r, --proto <protocol>                    Only show [tcp|udp] services
      -U, --up                                  Only show services which are up
      -o, --order <column>                      Order rows by specified column
      -S, --search <string>                     Search string to filter by
      <name1> <name2> ...                       Services to select


Command `creds`
===============
This command is used to manage the *credentials store*, i.e. credentials for targets in 
the current mission. This store is filled by two means:

* When a security check run by *Jok3r* finds new valid credentials,
* When the user explicitly provides credentials.

Running this command without any options will display currently saved 
credentials.

.. code-block:: console

    jok3rdb[default]> creds -h
    usage: creds [-h]
                 [--addcred <service-id> <user> <pass> | --addcred-http <service-id> <user> <pass> <auth-type> | --adduser <service-id> <user> | --adduser-http <service-id> <user> <auth-type> | -c <comment> | -d]
                 [-U <string>] [-P <string>] [-b | -u]
                 [-H <hostname1,hostname2...>] [-I <ip1,ip2...>]
                 [-p <port1,port2...>] [-s <svc1,svc2...>] [-o <column>]
                 [-S <string>]

    Credentials in the current mission scope

    optional arguments:
      -h, --help                                 show this help message and exit

    Manage credentials:
      --addcred <service-id> <user> <pass>       Add new credentials (username+password) for the given service
      --addcred-http <service-id> <user> <pass> <auth-type>
                                                 Add new credentials (username+password) for the specified authentication type on HTTP service
      --adduser <service-id> <user>              Add new username (password unknown) for the given service
      --adduser-http <service-id> <user> <auth-type>
                                                 Add new username (password unknown) for the specified authentication type on HTTP service
      -c, --comment <comment>                    Change the comment of selected cred(s)
      -d, --del                                  Delete selected credential(s) (instead of displaying)

    Filter credentials:
      -U, --username <string>                    Select creds with username matching this string
      -P, --password <string>                    Select creds with password matching this string
      -b, --both                                 Select creds where username and password are both set (no single username)
      -u, --onlyuser                             Select creds where only username is set
      -H, --hostname <hostname1,hostname2...>    Select creds for a list of hostnames (comma-separated)
      -I, --ip <ip1,ip2...>                      Select creds for a list of IPs (single IP/CIDR range comma-separated)
      -p, --port <port1,port2...>                Select creds a list of ports (single/range comma-separated)
      -s, --service <svc1,svc2...>               Select creds for a list of services (comma-separated)
      -o, --order <column>                       Order rows by specified column
      -S, --search <string>                      Search string to filter by

    Note: you can also use "services --addcred/--addonlyuser" to add new creds


Command `nmap`
==============
After creating a new mission into the database, it is necessary to add some targets 
(services). It can be done either manually - using ``services --add <host> <port> <service>``
or ``services --url <url>`` - or automatically from the results of a *Nmap* scan with the
``nmap`` command.

.. code-block:: console

    jok3rdb[default]> nmap -h
    usage: nmap [-h] [-n] <xml-results>

    Import Nmap results

    positional arguments:
      <xml-results>          Nmap XML results file

    optional arguments:
      -h, --help             show this help message and exit
      -n, --no-http-recheck  Do not recheck for HTTP services

Just issue the following command in order to import into the currently selected mission
all the services supported by *Jok3r* from results of a *Nmap* scan (in XML format):

.. code-block:: console

    jok3rdb[missionname]> nmap results.xml

.. note::
    When importing *Nmap* results, services *HTTPS/HTTP* are both added as *HTTP* services,
    and the distinction between cleartext and encrypted versions is done internally by using
    *Context-specific option* (*https*). It is the same for *SMTPS/SMTP*, *FTPS/FTP* and so on.

When importing *Nmap* results, *Jok3r* will recheck - by default - for *HTTP/HTTPS* services 
on all detected open ports that were not fingerprinted as such. This feature has been added
because - by experience - *Nmap* does not always detect all services serving web content when
they are on exotic ports.


Command `results`
=================
This command allows to view the outputs from tools run during security checks against
the various targets in the currently selected mission.

.. code-block:: console

    jok3rdb[default]> results -h
    usage: results [-h] [-s <check-id>] [<service-id>]

    Attacks results

    positional arguments:
      <service-id>           Service id

    optional arguments:
      -h, --help             show this help message and exit
      -s, --show <check-id>  Show results for specified check

For example, if you want to view the results for checks against the service with id 108
(refer to the column *id* in the output of the ``services`` command):

* First, issue the following command to get the list of checks that have been run against
  this particular service:

.. code-block:: console

    jok3rdb[missionname]> results 108

    [>] Attacks results:
    [>] Target: host=192.168.1.53 | port=16000/tcp | service http
    +----------+------------+------------------------------+------------+
    | Check id | Category   | Check                        | # Commands |
    +----------+------------+------------------------------+------------+
    | 211      | recon      | nmap-recon                   | 1          |
    | 212      | recon      | fingerprinting-app-server    | 1          |
    | 213      | recon      | fingerprinting-cms-wig       | 1          |
    | 214      | recon      | fingerprinting-cms-cmseek    | 1          |
    | 215      | recon      | crawling-fast                | 1          |
    | 216      | recon      | crawling-fast2               | 1          |
    | 217      | vulnscan   | nmap-vuln-lookup             | 1          |
    | 218      | vulnscan   | vulnscan-multi-nikto         | 1          |
    | 219      | vulnscan   | default-creds-web-multi      | 1          |
    | 220      | vulnscan   | http-put-check               | 1          |
    | 221      | vulnscan   | shellshock-scan              | 1          |
    | 222      | vulnscan   | jboss-vulnscan-multi         | 1          |
    | 223      | vulnscan   | jboss-status-infoleak        | 1          |
    | 224      | exploit    | jboss-deploy-shell           | 1          |
    | 225      | exploit    | struts2-rce-cve2017-5638     | 1          |
    | 226      | exploit    | struts2-rce-cve2017-9805     | 1          |
    | 227      | exploit    | struts2-rce-cve2018-11776    | 1          |
    | 235      | bruteforce | web-path-bruteforce-targeted | 1          |
    | 236      | bruteforce | web-path-bruteforce-opendoor | 1          |
    +----------+------------+------------------------------+------------+

* Then, you can display the outputs corresponding to a given check by specifying
  the *id* of the check as follows:

.. code-block:: console

    jok3rdb[missionname]> results -s 235

    [>] Results for check web-path-bruteforce-targeted:
    [>] Target: host=192.168.1.53 | port=16000/tcp | service http

    [>] cd /home/jbr/bitbucket/joker/toolbox/http/dirsearch; python3 dirsearch.py -u http://192.168.1.53:16000 -e jsp,java,do,txt,html,log -w /home/jbr/bitbucket/joker/wordlists/services/http/discovery/raft-large-directories.txt -f --exclude-status=400,404,500,000


     _|. _ _  _  _  _ _|_    v0.3.8
    (_||| _) (/_(_|| (_| )

    Extensions: jsp, java, do, txt, html, log | Threads: 10 | Wordlist size: 532797

    Error Log: /home/jbr/bitbucket/joker/toolbox/http/dirsearch/logs/errors-18-10-02_14-17-17.log

    Target: http://192.168.1.53:16000

    [14:17:17] Starting: 
    [14:17:20] 200 -    3KB - /test/
    [14:17:20] 200 -  474B  - /download.html
    [14:17:23] 200 -    7KB - /tools/
    [14:17:27] 200 -    8KB - /index.html
    [14:19:11] 200 -   26B  - /robots.txt

    Task Completed
