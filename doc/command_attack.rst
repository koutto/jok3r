================
Command `attack`
================

The command `attack` is where security checks against targets are started.

.. code-block:: console

    usage: python3 jok3r.py attack <args>

    optional arguments:
      -h, --help                             show this help message and exit

    Single target:
      Quickly define a target to run checks against it.

      -t, --target <ip[:port] | url>         Target IP[:PORT] (default port if not specified) or URL
      -s, --service <service>                Target service
      --add <mission>                        Add/update the target into a given mission scope
      --disable-banner-grab                  Disable banner grabbing with Nmap at start

    Multiple targets from a mission scope:
      Select targets from the scope of an existing mission.

      -m, --mission <mission>                Load targets from the specified mission
      -f, --filter <filter>                  Set of conditions to select a subset of targets
                                             (e.g "ip=192.168.1.0/24,10.0.0.4;port=80,8000-8100;service=http").
                                             Available filter options: ip, host, port, service, url, os
                                             Several sets can be combined (logical OR) by using the option multiple times

    Selection of checks:
      Select only some categories/checks to run against the target(s).

      --cat-only <cat1,cat2...>              Run only tools in specified category(ies) (comma-separated)
      --cat-exclude <cat1,cat2...>           Do not run tools in specified category(ies) (comma-separated)
      --checks <check1,check2...>            Run only the specified check(s) (comma-separated)

    Running option:
      --fast                                 Fast mode, disable prompts

    Authentication:
      Define authentication option if some credentials or single usernames are known.
      Options can be used multiple times. For multiple targets, the service for which 
      the creds/users will be used should be specified.

      --cred [<svc>[.<type>]] <user> <pass>  Credentials (username + password)
      --user [<svc>[.<type>]] <user>         Single username

    Context-specific options:
      Define manually some known info about the target(s).

      <opt1=val1 opt2=val2 ...>              Context-specific options, format name=value (space-separated)

There are 2 modes of attacks:

* Single target
* Multiple targets from a mission sccope in database


Single Target Mode
==================
This mode is used to run security checks against only one target. 

* Example to run checks against *MSSQL* service running on port 1433/tcp on 192.168.1.42:

.. code-block:: console

    python3 jok3r.py attack -t 192.168.1.42:1433 -s mssql

* Example to run checks against web application located at https://www.example.com/webapp/:

.. code-block:: console

    python3 jok3r.py attack -t https://www.example.com/webapp/

.. note::
    By default, *Jok3r* is run in interactive mode and so, will stop before running each
    check/command to ask for confirmation. It is usually useful when you want to have time
    to examine each result in live and decide whether it is needed to run the next check or
    if it can be skipped. However, you will often want to let *Jok3r* **running all the checks
    without any user interaction**, for better productivity, and check for the results at the
    end. To do so, add the option ``--fast`` to the command-line.

    Run checks against web application located at https://www.example.com/webapp/ without
    user interaction:

    .. code-block:: console

        python3 jok3r.py attack -t https://www.example.com/webapp/ --fast

**When doing a pentest, the proper way is to create a mission in the local database** 
(See :ref:`command-db`), and then if you run *Jok3r* against a single target that is in 
the scope of this mission, you should use the ``--add <missionname>`` option in order
**to push the target information and all the outputs from the security checks into the
database under the specified mission.**


Multiple Targets Mode
=====================
This mode is designed to work with the local database: First you create a mission
to define the scope of the pentest in the database (see :ref:`command-db`), and then
you run security checks against all or a subset a targets from the scope:

* Example to run checks against **all targets from the mission "MayhemProject"**, using 
  fast mode (i.e. without asking for any confirmation before targets and checks):

.. code-block:: console

    python3 jok3r.py attack -m MayhemProject --fast

* Example to run checks against **only FTP services running on ports 21/tcp and 2121/tcp 
  from the mission "MayhemProject"**, using fast mode:

.. code-block:: console

    python3 jok3r.py attack -m MayhemProject -f "port=21,2121;service=ftp" --fast

* Example to run checks against **only FTP services running on ports 2121/tcp and all
  HTTP services on 192.168.1.42**:

.. code-block:: console

    python3 jok3r.py attack -m MayhemProject -f "port=2121;service=ftp" -f "ip=192.168.1.42;service=http"

**The local database is automatically updated with the results** from the security checks
run by *Jok3r*.


Miscellaneous Options
=====================

Selection of Checks
-------------------
When running the ``attack`` command, it is possible to make a selection of checks to run:

* ``--checks <check1,check2...>``: Run only the given checks against targets. It might even be
  a single check. Use ``python3 info --checks <service>`` in order to get the list of available
  checks for the targeted service (see :ref:`command-info`).

* ``--cat-only <cat1,cat2...>``: Run only checks that are classified under one or several
  categories (e.g. "recon").

* ``--cat-exclude <cat1,cat2...>``: Run all categories of checks except the one(s) specified.


Authentication
--------------
It is also possible to define some authentication options if credentials - or only valid
usernames - are known on the targets.

Let's take several examples:

* When you want to run attack against all targets in the scope of mission "MayhemProject" and you 
  already know credentials of all *MSSQL* instances in the scope:

.. code-block:: console

    python3 jok3r.py attack -m MayhemProject --cred mssql sa password --fast

* When you want to scan a web application running on a *JBoss* server (and add the target to 
  the mission "MayhemProject"), and you already know *JBoss* credentials:

.. code-block:: console

    python3 jok3r.py attack -t http://www.example.com --cred http.jboss manager password --add MayhemProject --fast

* When you want to scan a Wordpress website, and you know a valid admin username (but no
  valid password):

.. code-block:: console

    python3 jok3r.py attack -t http://www.targetwordpress.com --user http.wordpress wordpressadmin --fast


Context-specific Options
------------------------
In *Jok3r*, Context-specific options are options that give specifications about a
service.

.. warning::
    Usually, you don't have to bother specifying context-specific options manually
    in *Jok3r* command-line because it does its best to set and update them using
    *SmartModules*. However, you might still want to force the value of some of them 
    in some situations.

Available context-specific options depends on the service.

There are 3 supported types of context-specific options:

* **Boolean**,
* **Value from a given list**,
* **Variable**.

To better understand, here are some example of supported context-specific options
for *HTTP*:

* ``https`` (boolean): Set to *true* when SSL/TLS is used.
* ``webdav`` (boolean): Set to *true* when *WebDav* is supported.
* ``language``: Allows to set the language of the targeted web application, can be 
  one of the value in the list defined in ``http.conf`` settings file (e.g. java, php, 
  asp, angularjs, coldfusion).
* ``cms``: Allows to set the name of the CMS in use if relevant (wordpress, joomla, 
  drupal, mambo, silverstripe, vbulletin, magento...)
* ``server``: Allows to set the name of the server (iis, glassfish, jboss, jenkins, 
  tomcat, weblogic...)


