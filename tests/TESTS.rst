
======
TESTS
======



AJP
======

.. code-block:: console

    https://github.com/Paritosh-Anand/Docker-Httpd-Tomcat


FTP
======

.. code-block:: console

    sudo docker run -d -v /tmp/:/home/vsftpd -p 20:20 -p 21:21 -p 21100-21110:21100-21110 \
    -e FTP_USER=ftp -e FTP_PASS=s3curity \
    -e PASV_ADDRESS=127.0.0.1 -e PASV_MIN_PORT=21100 -e PASV_MAX_PORT=21110 \
    --name vsftpd --restart=always fauria/vsftpd

- [x] Weak creds


HTTP
======

- Coldfusion:

    - [ ] CVE-2010-2861 - https://github.com/vulhub/vulhub/tree/master/coldfusion/CVE-2010-2861
    - [ ] CVE-2017-3066 - https://github.com/vulhub/vulhub/tree/master/coldfusion/CVE-2017-3066

- Glassfish:

    - [ ] CVE-2017-1000028 path traversal - https://github.com/vulhub/vulhub/tree/master/glassfish/4.1.0

- JBoss:

    - [ ] CVE-2017-7504 - https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-7504
    - [ ] CVE-2017-12149 - https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149
    - [ ] JBoss JMXInvokerServlet (jexboss)

- Weblogic:

    - [x] cve-2017-10271_weblogic - https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2017-10271
    - [x] cve-2018-2628_weblogic - https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2018-2628
    - [x] cve-2018-2894_weblogic_1 - https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2018-2894

- Websphere:

- Drupal:

    - [ ] Drupalgeddon CVE-2014-3704 - https://github.com/vulhub/vulhub/tree/master/drupal/CVE-2014-3704
    - [x] Drupalgeddon 2 CVE-2018-7600 - https://github.com/vulhub/vulhub/tree/master/drupal/CVE-2018-7600
    - [ ] CVE-2018-7602 - https://github.com/vulhub/vulhub/tree/master/drupal/CVE-2018-7602

- Joomla:

    - [x] Weak creds
    - [x] CVE-2017-8917 - https://github.com/vulhub/vulhub/tree/master/joomla/CVE-2017-8917


JAVA-RMI
========

- JMX:

    https://github.com/cstroe/java-jmx-in-docker-sample-app

    .. code-block:: console

        ./mvnw package
        docker-compose up --build

    - [x] JMX auth disabled
    - [ ] Deserialize


JDWP
======



MSSQL
======

.. code-block:: console

    sudo docker run -e 'ACCEPT_EULA=Y' -e 'SA_PASSWORD=Password123' -e 'MSSQL_PID=Express' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2017-latest-ubuntu

- [x] Weak creds
- [x] Post-authentification checks

MYSQL
======

- [x] CVE-2012-2122 - https://github.com/vulhub/vulhub/tree/master/mysql/CVE-2012-2122


ORACLE
=======

.. code-block:: console

    Install:
    git clone https://github.com/wnameless/docker-oracle-xe-11g.git
    sudo docker build -t docker-oracle-xe-11g .

    Run:
    sudo docker run -d -p 49161:1521 -e ORACLE_ALLOW_REMOTE=true docker-oracle-xe-11g

    Test:
    sqlplus system/oracle@localhost:49161

    Creds:
    hostname: localhost
    port: 49161
    sid: xe
    username: system
    password: oracle

- [x] Weak creds
- [x] TNS Poisoning
- [x] SID guessing
- [x] Post-auth checks


POSTGRESQL
==========

- [x] Default creds + CVE-2019-9193 - https://github.com/vulhub/vulhub/tree/master/postgres/CVE-2019-9193


RDP
======
- [x] Standard RDP

RPC
======
- [x] Anonymous NFS shares


SMB
======
- [x] SMB anonymous
- [x] SMB authenticated limited account
- [x] SMB authenticated privileged account


SMTP
=====

.. code-block:: console

    sudo docker run -p 25:25 namshi/smtp

- [x] User enum
- [x] SMTP Relay


SNMP
=====

.. code-block:: console

    sudo docker run -d --name snmpd -p 161:161/udp polinux/snmpd

- [x] Default community string


SSH
====
- [x] CVE-2018-10933 libssh auth bypass - https://github.com/vulhub/vulhub/tree/master/libssh/CVE-2018-10933
- [ ] CVE-2018-15473


TELNET
=======
- [x] Bruteforce. PARTIAL => some telnet services are very slow and make Hydra hanging forever... + Error "Not a Telnet Service" - Bruteforce


VNC
====

.. code-block:: console

    sudo docker run -d -p 5901:5901 -p 6901:6901 consol/centos-xfce-vnc
    vncviewer localhost:5901    (password: vncpassword)

- [x] Bruteforce (blacklisting timeout scheme)