============
Why Jok3r ?
============

For pentesting, there are a lot of open-source tools/scripts available out there 
on the Internet that might be useful. Some of them are just proofs of concept or 
simple scripts aimed at achieving one single simple task, while others are much 
more complex projects. Some of them are a bit outdated but still relevant in some 
cases, while others are updated regularly with a very active community (e.g 
Metasploit project).

.. note::
	Most of the available open-source hacking tools are now available on 
	https://github.com. Moreover, some cool websites such as https://www.kitploit.com 
	or http://seclist.us are doing a great job referencing some new hacking tools 
	and their major updates.

As a pentester, it as appeared to me that there are some boring stuffs that might be 
automated or at least semi-automated.


About Toolbox Management
========================
* It is always boring to keep a complete toolbox for network/web pentests with 
  up-to-date tools, and with all required dependencies.

* Kali Linux is good but does not embed all the hacking tools I find useful.

* Big projects such as Metasploit are very great, but unfortunately they do not 
  provide all the features that might be useful during pentests: some modules are 
  outdated and/or buggy, some modules/exploits are missing, etc.

* There are lots of tools/scripts/proof-of-concepts that are released by security 
  enthusiasts in order to achieve some more or less specific tasks (e.g. vulnerability 
  scan against a specific technology/product, exploit for a given vulnerability, 
  fingerprinting...) but it is always hard to keep track of all those releases, 
  and most importantly to remember using them in the appropriate context during
  pentests.

* There is no perfect tool, and everyone has its advantages and drawbacks. For
  example, when pentesting a Wordpress websites, there are various tools for
  vulnerability scanning in this CMS (*WPScan*, *wpseku*, *CMSmap*, etc.). All those
  tools do not rely on the same vulnerability database, do not have the same update
  status at the time of the use, might not use the same techniques, and so on.
  By experience, it has appeared that **it is often better to combine tools**.
  One can reports a vulnerability that has not been detected by the others, and
  inversely.

.. warning::
	The purpose of *Jok3r* is not to turn you into a Script-Kiddie. A good
	pentester knows what his tools are doing. However, the reality is that he has
	to rely on tools to save a lot of time, and to avoid to re-invent the wheel !


About using Hacking Tools
=========================
* Infrastructure/web pentests are always following the same process: 
	1. Port scanning, 
	2. Fingerprinting, 
	3. Vulnerability scanning, 
	4. Exploitation of detected vulnerabilities, 
	5. Bruteforce attack if needed, 
	6. Post-exploitation. 

* During a pentest with a limited amount of time, a lot of these steps are actually 
  done by running some tools. The selection of tools and commands to run actually 
  depends on: 
	* Targeted services (result of port scanning), 
	* Technologies/products in use (result of fingerprinting), 
	* Credentials on the target (already known/compromised via bruteforce ? only 
	  valid usernames ? nothing ?)

* Basically, doing all that automated stuff is usually boring and what we want is 
  to spend the least amount of time on everything that can be automated, in order to 
  be able to spend more time on manual testing and research of more tricky/unobvious 
  vulnerabilities on the targets.

* Note that we cannot only rely on commercial all-in-one vulnerability scanners such 
  as *Nessus* because - by experience - it does not detect some typical vulnerabilities 
  that might be easy to spot using some dedicated simple scripts.


Combine Open-Source Hacking Tools
=================================
*Jok3r* tries to solve the enumerated problems. **It is useless to try to re-invent 
the wheel: lots of hacking tools/scripts are already available out there, they should 
be aggregated together in a smart way.**
