.. _command-info:

===============
Command `info`
===============

The command `info` is useful to get a quick overview of Jok3r settings.

.. code-block:: console

    usage: python3 jok3r.py info <args>

    optional arguments:
      -h, --help          show this help message and exit

    Info:
      --services          List supported services
      --options           List supported context-specific options
      --http-auth-types   List the supported HTTP authentication types
      --checks <service>  List all the checks for the given service


Supported subcommands are pretty straightforward:

* ``--services``: Display the list of services that are supported (can be targeted).

.. note::
    In Jok3r, there is a special service which is named `multi`. It is used 
    internally in order to group all the tools from toolbox that can be used 
    to target different services (and not only one single service). For example, 
    `Nmap` and `Metasploit` can both be used to perform tests against different 
    kinds of services - such as http, ftp, ssh... - thus they are classified under 
    this special service `multi`.

* ``--options``: Display the list of supported context-specific options.

.. note::
    A context-specific option TODO

* ``--http-auth-types``: List the supported HTTP authentication types. Here are
  some examples:

    * wordpress
    * drupal
    * tomcat
    * jboss
    * weblogic

* ``--checks <service>``: List the security checks that are implemented for the
  given service. 

.. note::
    Security checks are defined into configuration files located into the
    ``settings/`` directory. For each service, there is a ``settings/<service>.conf``
    file that can be easily customized.
