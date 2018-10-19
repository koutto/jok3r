
==========
Internals
==========

TODO

Tree structure
==============
The project is structured in folders as such:

* [lib] - Contains the source code
  * [controller] - The controller interface between the cli and the logic (based on MVC design)
  * [core] - Contains the core classes of the project which handles the logic of the app 
  * [output] - Contains classes used for CLI output
  * [utils] - Contains utility classes
* [output] - Default directory where results are stored
* [pictures] - Logo and images
* [settings] - Contains configuration files. One .conf file per service. Easily editable
* [toolbox] - Directory where the tools are installed.  
  * [service_name] - For each service, a sub-directory is created when installing toolbox
    * [tool_01] -
    * [tool_02]
  * ...
* [wordlists] - Default wordlists aimed at being used by some tools
* README.txt - This file
* requirements.txt - Pip requirements file (required Python libraries)
* jok3r.py - The main program. This is the script that the user needs to run.