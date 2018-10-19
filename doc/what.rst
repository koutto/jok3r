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

To achieve that, it **combines open-source Hacking tools to run various security checks
against all common network services.**


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

.. note::
	*Jok3r* has been built with the ambition to be easily and quickly customizable: 
	Tools, security checks, supported network services... can be easily 
	added/edited/removed by editing settings files with an easy-to-understand syntax.