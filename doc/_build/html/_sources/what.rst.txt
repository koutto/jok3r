===============
What is Jok3r ?
===============

Network and Web Pentest Framework
=================================
*Jok3r* is a Python3 CLI application which is aimed at **helping penetration testers 
for network infrastructure and web black-box security tests**. 

Overview
========
Its main goal is to **save time on everything that can be automated during network/web
pentest in order to enjoy more time on more interesting and challenging stuff**.

To achieve that, it **combines open-source Hacking tools to perform 
reconnaissance, vulnerability scanning, exploitation, bruteforce and (basic) post-exploitation
against all common network services.**


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

.. note::
	*Jok3r* has been built with the ambition to be easily and quickly customizable: 
	Tools, security checks, supported network services... can be easily 
	added/edited/removed by editing settings files with an easy-to-understand syntax.