========
Settings
========

In *Jok3r*, **settings are fully and easily customizable**. This is one of
the goal of the tool: **Make it evolve quickly**. This page explains how settings
files stored in the ``settings/`` directory work and can be edited.

Toolbox Settings
================
Toolbox settings are stored in the file ``settings/toolbox.conf``. This is where all tools
used by *Jok3r* are referenced and configured.

As an example, here is a snippet from the file:

.. code-block:: text

    [...]

    [patator]
    name           = patator
    description    = Multi-purpose brute-forcer, with a modular design and a flexible usage
    target_service = multi
    install        = git clone https://github.com/lanjelot/patator.git .
    update         = git pull
    check_command  = python2.7 patator.py -h

    [clusterd]
    name           = clusterd
    description    = Application server attack toolkit (JBoss, ColdFusion, Weblogic, Tomcat, Railo, Axis2, Glassfish)
    target_service = http
    install        = git clone https://github.com/hatRiot/clusterd.git . && sudo pip2 install -r requirements.txt
    update         = git pull && sudo pip2 install -r requirements.txt
    check_command  = python2.7 ./clusterd.py -h

    [...]

Format of this configuration file is pretty straightforward. For each tool, 
a section is created using the syntax ``[toolname]`` and the following options
can/must be specified:

* **name (mandatory)**: The name of the tool as it will be displayed. Authorized charset 
  is ``[a-z0-9_-]``.
* **description (mandatory)**: A Short text describing the tool.
* **target_service (mandatory)**: Service that can be targeted using this tool 
  (e.g. http for *Nikto*). For services such as *Nmap*, *Metasploit* and so on, that can
  be used to target several kinds of service, use the special service name "multi".
* **install (optional)**: Command-line to use in order to install the tool. It supports 
  the use of some tags (See `Tags for Commands`_). It is considered
  as optional because *Jok3r* allows to insert in the toolbox some tools that are not
  directly handled by it; it is for example the case for *Nmap* and *Metasploit* by default. 
  But note that if you don't supply installation command, you will not be able to control
  the installation of the tool from *Jok3r* and it is thus not advised to do so.
* **update (optional)**: Command-line to use in order to update the tool. Basically,
  take the same consideration as with the *install* option.
* **check_command (optional)**: Command-line to use in order to check for a correct install.
  Usually, it just consists in running the tool without any argument or with the standard
  ``-h`` option to see if everything seems working well after a fresh install (no 
  dependencies errors or such). This option can be omitted.


Services Settings
=================
For each service, settings are stored in file ``settings/<service>.conf``.
There is **one configuration file per service** which contains global parameters and then
the settings related to all security checks (for this service).

Global settings for a Service
-----------------------------
As an example, here is the beginning of the configuration file for *HTTP*, i.e. 
``settings/http.conf``:

.. code-block:: text
    
    [config]
    default_port = 80
    protocol     = tcp
    categories   = recon, vulnscan, exploit, bruteforce
    auth_types   = glassfish, jboss, jenkins, lotusdomino, tomcat, weblogic, websphere, wordpress, joomla, drupal, opencart, magento

    [specific_options]
    https    = boolean
    webdav   = boolean
    language = list
    cms      = list
    server   = list 

    [supported_list_options]
    supported_language = java, php, asp, angularjs, coldfusion
    supported_cms      = wordpress, joomla, drupal, mambo, silverstripe, vbulletin, magento, prestashop, liferay, opencart, dotnetnuke, django-cms, concrete5, punbb, moodle, cms-made-simple
    supported_server   = iis, glassfish, jboss, jenkins, tomcat, weblogic, lotusdomino

Every ``<service>.conf`` file begins with special following sections:

* ``[config]``: The basic configuration about the service. It contains the following options:

    * **default_port (mandatory)**: The default port number for the service.
    * **protocol (mandatory)**: The protocol (tcp or udp) for the service.
    * **categories (mandatory)**: List of different categories of checks supported for the service. 
      Authorized charset is ``[a-z0-9_-]``.
    * **auth_types (optional)**: List of authentication types that are supported for the service.
      Actually, only relevant for *HTTP* (where there are different possible authentications: *Tomcat, 
      JBoss, Wordpress, Joomla...*). Authorized charset is ``[a-z0-9_-]``.

* ``[specific_options]``: Contains the list of available context-specific options for the service.

    * **For each option, the name** (authorized charset is ``[a-z0-9_-]``) **is used as key** and
      the type as value. Supported types are:

        * ``boolean`` for boolean options. It is also possible to add the default value: 
          ``boolean:True`` means a boolean option which value is *True* if the option is not set.
          Note that ``boolean:False`` is redundant with ``boolean`` because *False* is the default.
        * ``list`` for options taking their value into a defined list (in ``[supported_list_options]``
          section, see below).
        * ``var`` for option of type variable.

* ``[supported_list_options]``: This section is used only if there is at least one context-specific
  option with the type ``list``. 

        * For each option of type ``list``, a key named **supported_<optionname>** is created and it 
          takes as value the list of authorized/supported values for the option.

.. note::
    For overall consistency, take care to use standard category names, among:

    * recon
    * vulnscan
    * exploit
    * bruteforce
    * postexploit


Security Checks for a Service
-----------------------------
For example, here are the settings of two checks as defined inside ``settings/http.conf``:

.. code-block:: text

    [check_jboss-deploy-shell]
    name        = jboss-deploy-shell
    category    = exploit
    description = Try to deploy shell on JBoss server (jmx-console, web-console, admin-console, JMXInvokerServlet)
    tool        = jexboss
    command_1   = python2.7 jexboss.py --auto-exploit --jboss -u [URL] --cmd whoami
    context_1   = { 'server': 'jboss', 'auth_status': NO_AUTH, 'auth_type': 'jboss' }
    command_2   = python2.7 jexboss.py --auto-exploit --jboss -u [URL] --jboss-login '[USERNAME]:[PASSWORD]' --cmd whoami
    context_2   = { 'server': 'jboss', 'auth_status': POST_AUTH, 'auth_type': 'jboss' }

    [check_web-path-bruteforce-targeted]
    name        = web-path-bruteforce-targeted
    category    = bruteforce
    description = Bruteforce web paths when language is known (extensions adapted) (use raft wordlist)
    tool        = dirsearch
    command_1   = python3 dirsearch.py -u [URL] -e jsp,java,do,txt,html,log -w [WORDLISTSDIR]/services/http/discovery/raft-large-directories.txt -f --exclude-status=400,404,500,000
    context_1   = { 'language': 'java' }
    command_2   = python3 dirsearch.py -u [URL] -e php,txt,html,log -w [WORDLISTSDIR]/services/http/discovery/raft-large-directories.txt -f --exclude-status=400,404,500,000
    context_2   = { 'language': 'php' }
    command_3   = python3 dirsearch.py -u [URL] -e asp,aspx,txt,html,log -w [WORDLISTSDIR]/services/http/discovery/raft-large-directories.txt -f --exclude-status=400,404,500,000
    context_3   = { 'language': 'asp' }
    command_4   = python3 dirsearch.py -u [URL] -e js,txt,html,log -w [WORDLISTSDIR]/services/http/discovery/raft-large-directories.txt -f --exclude-status=400,404,500,000
    context_4   = { 'language': 'angularjs' }
    command_5   = python3 dirsearch.py -u [URL] -e cfm,txt,html,log -w [WORDLISTSDIR]/services/http/discovery/raft-large-directories.txt -f --exclude-status=400,404,500,000
    context_5   = { 'language': 'coldfusion' }

Actually, each security check is defined under a section named ``[check_<check-name>]``
(authorized charset is ``[a-z0-9_-]``) by using the following options:

* **name (mandatory)**: The name of the tool as it will be displayed. Authorized 
  charset is ``[a-z0-9_-]``.
* **category (mandatory)**: Category inside which this check is classified. The name
  of the category must be in the list given in the option **categories** under the 
  section ``[config]`` at the beginning of the configuration file.
* **description (mandatory)**: Short text describing the check.
* **tool (mandatory)**: Name of the tool to use in this check. It must correspond
  exactly to the name which is given in ``toolbox.conf``.
* Each check is defined by one or several commands to run. For each command, you 
  should consider:

    * **command_<number> (mandatory)**: Command-line to run. It supports the use of multiple 
      tags (See `Tags for Commands`_)   
    * **context_<number> (optional)**: Context that must be met to run the corresponding
      command (See `Context Syntax`_)

* **postrun (optional)**: Name of a method from :ref:`smartmodules` to run after each/the
  command.


Tags for Commands
=================
Commands in settings supports the use of several tags. At runtime, they are replaced
by the correct values.

**For the commands in settings "install" and "update" in** ``settings/toolbox.conf``:

* ``[TOOLBOXDIR]``: Absolute path of toolbox directory.

**For the commands in setting "command_<number>" of security checks in** ``settings/<service>.conf``:

* ``[IP]``: The target IP address.
* ``[URL]``: The target URL (when target service is *HTTP*).
* ``[HOST]``: The target host (if not provided or reverse DNS lookup does not returns anything,
  IP address is used instead).
* ``[PORT]``: Target port number.
* ``[PROTOCOL]``: Protocol to use, either TCP or UDP.
* ``[SERVICE]``: Target service name.
* ``[WEBSHELLSDIR]``: Absolute path of directory storing webshells (useful for some exploits
  against *HTTP* services).
* ``[WORDLISTSDIR]``: Absolute path of directory storing wordlists.
* ``[USERNAME]``: Username for target from credentials store. This tag is supported for *Context* 
  (See `Context Syntax`_) with ``auth_status=USER_ONLY`` (only valid username is known), 
  or ``auth_status=POST_AUTH`` (valid username+password are known). If there are several
  usernames for the target in credentials store, the command is run for every username.
* ``[PASSWORD]``: Password for target from credentials store. This tag is supported for 
  *Context* with ``auth_status=POST_AUTH`` (valid username+password are known).
* ``[LOCALIP]``: Local IP address (might be useful for some exploits that perform reverse
  connection).


Specific tags depending on context-specific options are also supported by the service.
    
* **For context-specific option of type boolean**:
  ``[OPTION_NAME true="text to use if option is True"]``

* **For context-specific option of type list**:
  ``[OPTION_NAME element1="val1" element2="val2" ... default="default val" ]`` 
  If the option has the value "element1",
  - respectively "element2" - the tag will be replaced by "val1" - respectively "val2".
  If the value of the option does not match anything specified in the tag, the tag
  will be replaced by "default val" ("default" parameter optional).

* **For context-specific option of type var**:
  ``[OPTION_NAME set="text _VAR_ text" default="default text"]``

    * If variable is set, it is replaced by the text into "set" parameter 
      with "_VAR_" replaced by variable's value.
    * Otherwise, it is replaced by the text into "default" parameter if existing
      (optional parameter).


Context Syntax
==============
For each command in setting "command_<number>" of security checks in ``settings/<service>.conf``,
it is possible to specify a context. **A context defines the required conditions to run 
the command**.

For the setting "command_<number>", a context can be defined in setting "context_<number>"
(<number> must match). The context is defined using a Python dictionary.

Here is an example for a command in a security check against *HTTP*: 

.. code-block:: text

    command_2   = python2.7 jexboss.py --auto-exploit --jboss -u [URL] --jboss-login '[USERNAME]:[PASSWORD]' --cmd whoami
    context_2   = { 'server': 'jboss', 'auth_status': POST_AUTH, 'auth_type': 'jboss' }

The value of "context_2" means that "command_2" must be run **if and only if the following 
conditions are met**:

* The context-specific option ``server == 'jboss'``, i.e. the target *HTTP* service is using
  *JBoss* server.
* Valid credentials for *JBoss* on the targeted service are present in the credentials store in
  the database.

More generally, **conditions that can be defined in context are**:

* **Values of context-specific options**,
* **Authentication status on the target** via the key ``auth_status`` that can take either 
  of the following values:
  
    * ``NO_AUTH``: No credentials are known,
    * ``USER_ONLY``: At least one username is known,
    * ``POST_AUTH``: Valid credentials (username+password) are known,
    * ``None``: Any status.

.. warning::
    For *HTTP* only, if ``auth_status`` is used to define a context, it is mandatory to 
    specify for which kind of authentication does that must apply via the key ``auth_type``
    (in the previous example, it was for "jboss").