=========
Changelog
=========
**v3.0 BETA 3** 2020-07-18
	* Add waf-checker and Pentest1 to attacks profiles
	* Fix several minor bugs and customizations

**v3.0 BETA 2** 2019-07-09
	* Fix several bugs after testings
	* Add/fix/improve matchstrings
	* Add/fix/improve checks
	* Changes in database structure to store more info related to hosts (OS, device type, vendor)
	* Update on HTML reporting templates (more user-friendly)

**v3.0 BETA** 2019-04-23
	* Support for products detection based on checks outputs (e.g web-server, web-appserver, ftp-server...)
	* Support for vulnerabilities detection based on checks outputs (still experimental !)
	* Database structure updated to be able to work with products and vulnerabilities
	* Add search feature in local database
	* Full redesign of smartmodules aimed at updating the context (based on regex for creds, options, products & vulns)
	* Improve web technologies detection at beginning of attacks against HTTP services
	* Add many checks/tools
	* Add CVE lookup when product name & version have been detected
	* Add HTML reporting (with screenshot support for HTTP services)
	* Improve web content discovery (smart choice of wordlists based on the context)
	* Add support for custom attack profiles (pre-selection of checks)
	* Targets initialization optimization
	* Add support for --userlist and --passlist to use custom wordlists for bruteforce checks
	* Improve context requirement feature
	* Code refactoring and code docstrings
	* Fix many bugs

**v2.0** 2018-10-19
	* Everything rebuilt from scratch
	* Python3 compatibility
	* Local database to store targets and results from checks
	* Context awareness to run only relevant checks against targets
	* Post processing of checks outputs possible, in order to update context
	* Dockerization
	* Add lots of checks based on various tools
	* Add supported services
	* ...and many more

**v1.1**
    * Many bug fixes
    * Add lots of services/tools
    * Improve wordlists
    * Support for "multi-services" tools (tools that can be used differently for targeting different services)
    * Change a bit of settings logic: Now, install status and last update time are stored into an external file called "_install_status.conf"

**v1.0** 2017-03-10 
	* First release