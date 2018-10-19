
.. image:: ./pictures/logo.png

==========================================
Jok3r - Network and Web Pentest Framework
==========================================

*Jok3r* is a Python3 CLI application which is aimed at **helping penetration testers 
for network infrastructure and web black-box security tests**. 

Main features
=============
* **Toolbox management**: Install automatically all the hacking tools that are used by
  *Jok3r* and keep them up-to-date.

* **Attack automation**: Run security checks against network services (including web) 
  by chaining various hacking tools. *Jok3r* does its best to become aware of the context
  of the target and run the checks accordingly (depending on the technology in use, the
  knowledge of valid credentials or not, etc.)

* **Mission management**: Targets can be classified by missions and stored into a local
  database. It stores all information related to targeted services and results of the 
  security checks that have been run. It is similar to the *Metasploit* database.

*Jok3r* has been built with the ambition to be easily and quickly customizable: 
Tools, security checks, supported network services... can be easily 
added/edited/removed by editing settings files with an easy-to-understand syntax.


Installation
============
**The recommended way to use Jok3r is inside a Docker container so you will not have 
to bother about dependencies and installing the whole toolbox.**

A Docker image is available and maintained on Docker Hub at 
https://hub.docker.com/r/koutto/jok3r-docker/. It is initially based on official Kali
Linux Docker image (kalilinux/kali-linux-docker).

**Pull Jok3r Docker Image**

.. code-block:: console

    sudo docker pull koutto/jok3r-docker

**Run fresh Docker container**

.. code-block:: console

    sudo docker run -i -t --name jok3r-container -w /root/jok3r koutto/jok3r-docker

Jok3r and its toolbox is ready-to-use !


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


