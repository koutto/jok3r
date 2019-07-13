#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Config
###
import colored
import os

from lib.core.Constants import *
from lib._version import __version__


#----------------------------------------------------------------------------------------
# Banner/Help

BANNER = colored.stylize("""

                          `-:/++++/:-.    .-:/++++/:-`                                    
                        .:ohdddmmmmdd.\  /.dddmmmmdddho:.                                
                      `:ydmmmmmmmmmmmmm\/mmmmmmmmmmmmmmdy:`                         
                     `+dmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmd+`                     
                    +dyo+++oshmmmmmmmmmmmmmmmmmmmmhso+++oyd+                    
                  -+-         .dmmmmmmmmmmmmmmmmd.         -+-                  
                 ``           `dmmmmmmmmmmmmmmmmd`           ``                 
                              `dmmmmmmmmmmmmmmmmd`                              
                              `ymmmmmmmmmmmmmmmmy`                              
                                .+dmmmmmmmmmmd+.                                
                                   /dmmmmmmd/                                   
                                    `odmmdo`                                    
                                      .hh.                                      
                                                        
                                                                   
                       ██╗ ██████╗ ██╗  ██╗██████╗ ██████╗ 
                       ██║██╔═══██╗██║ ██╔╝╚════██╗██╔══██╗
                       ██║██║   ██║█████╔╝  █████╔╝██████╔╝
                  ██   ██║██║   ██║██╔═██╗  ╚═══██╗██╔══██╗
                  ╚█████╔╝╚██████╔╝██║  ██╗██████╔╝██║  ██║  v{version}
                   ╚════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝ 
                  
                  [ Network & Web Pentest Automation Framework ]

""".format(version=__version__), colored.fg('light_green') + colored.attr('bold'))

USAGE = """
python3 jok3r.py <command> [<args>]

Supported commands:
   toolbox    Manage the toolbox
   info       View supported services/options/checks
   db         Define missions scopes, keep tracks of targets & view attacks results
   attack     Run security checks against targets
   
"""

ATTACK_EXAMPLES = colored.stylize('Examples:', colored.attr('bold')) + """
  - Run all security checks against an URL in interactive mode (break before each check):
  python3 jok3r.py attack -t http://www.example.com/ 

  - Run all security checks against a MS-SQL service (without user interaction) and add results to the mission "mayhem" in db:
  python3 jok3r.py attack -t 192.168.1.42:1433 -s mssql --add2db mayhem --fast

  - Run only "recon" and "vulnscan" security checks against an FTP service and add results to the mission "mayhem" in db:
  python3 jok3r.py attack -t 192.168.1.142:21 -s ftp --cat-only recon,vulnscan --add2db mayhem

  - Run security checks against all FTP services running on 2121/tcp and all HTTP services from the mission "mayhem" in db:
  python3 jok3r.py attack -m mayhem -f "port=2121;service=ftp" -f "service=http"

  - Search for "easy wins" (critical vulns / easy to exploit) on all services registered in mission "mayhem" in db:
  python3 jok3r.py attack -m mayhem --profile red-team --fast
"""

DB_INTRO = """
The local database stores the missions, targets info & attacks results.
This shell allows for easy access to this database. New missions can be added and
scopes can be defined by importing new targets.
"""


#----------------------------------------------------------------------------------------
# Arguments Parsing Settings

ARGPARSE_MAX_HELP_POS    = 45
TARGET_FILTERS           = {
    'ip'       : FilterData.IP, 
    'host'     : FilterData.HOST,
    'port'     : FilterData.PORT, 
    'service'  : FilterData.SERVICE, 
    'url'      : FilterData.URL,
    'osfamily' : FilterData.OS_FAMILY,
    'banner'   : FilterData.BANNER,
}


#----------------------------------------------------------------------------------------
# Basic Settings

TOOL_BASEPATH      = os.path.dirname(os.path.realpath(__file__+'/../..'))
TOOLBOX_DIR        = TOOL_BASEPATH + '/toolbox'
DEFAULT_OUTPUT_DIR = 'output'
WEBSHELLS_DIR      = TOOL_BASEPATH + '/webshells'
WORDLISTS_DIR      = TOOL_BASEPATH + '/wordlists'
DB_FILE            = TOOL_BASEPATH + '/local.db'
DB_HIST_FILE       = TOOL_BASEPATH + '/.dbhistory'
REPORT_TPL_DIR     = TOOL_BASEPATH + '/lib/reporter/templates'
REPORT_PATH        = TOOL_BASEPATH + '/reports'


#----------------------------------------------------------------------------------------
# Display Settings

ATTACK_SUMMARY_TABLE_MAX_SIZE = 18

#----------------------------------------------------------------------------------------
# Settings Files

SETTINGS_DIR              = TOOL_BASEPATH + '/settings'
CONF_EXT                  = '.conf'
TOOLBOX_CONF_FILE         = 'toolbox'
INSTALL_STATUS_CONF_FILE  = '_install_status'
ATTACK_PROFILES_CONF_FILE = 'attack_profiles'
PREFIX_SECTION_CHECK      = 'check_'
MULTI_CONF                = 'multi'
MULTI_TOOLBOX_SUBDIR      = 'multi'

TOOL_OPTIONS = {
    MANDATORY: [
        'name',
        'description',
        'target_service',
    ],
    OPTIONAL: [
        'install',
        'update',
        'check_command',
    ]
}

SERVICE_CHECKS_CONFIG_OPTIONS = {
    MANDATORY: [
        'default_port',
        'protocol',
        'categories',
    ],
    OPTIONAL: [
        'auth_types'
    ]
}

CHECK_OPTIONS = {
    MANDATORY: [
        'name',
        'category',
        'description',
        'tool',
        # command
    ],
    OPTIONAL: [
        'apikey',
    ]
}

OPTIONS_ENCRYTPED_PROTO = (
    'ftps',
    'https',
    'rmissl',
    'telnets',
)


#----------------------------------------------------------------------------------------
# Services

# Service names matching between Nmap and Jok3r
# In particular, unencrypted and encrypted versions of the same protocol are 
# differentiated in Nmap (e.g. smtp/smtps, http/https, etc.), but in Jok3r this 
# distinction is done by context-specific options
SERVICES_NMAP_TO_JOKER = {
    'ajp13'         : 'ajp',
    'ftp-agent'     : 'ftp',
    'ftp-proxy'     : 'ftp',
    'ftps'          : 'ftp',
    'microsoft-ds'  : 'smb',
    'netbios-ns'    : 'smb',
    'ms-sql2000'    : 'mssql',
    'ms-sql-m'      : 'mssql',
    'ms-sql-s'      : 'mssql',
    'ms-wbt-server' : 'rdp',
    'rmiregistry'   : 'java-rmi',
    'http-alt'      : 'http',
    'http-mgmt'     : 'http',
    'http-proxy'    : 'http',
    'http-wmap'     : 'http',
    'https'         : 'http',
    'https-alt'     : 'http',
    'https-wmap'    : 'http',
    'ssl/http'      : 'http',
    'ssl/https'     : 'http',
    'ssl/ssl'       : 'http',
    'oracle-tns'    : 'oracle', 
    'smtps'         : 'smtp',
}

# Service names matching between Shodan and Jok3r
# In particular, unencrypted and encrypted versions of the same protocol are 
# differentiated in Shodan (e.g. smtp/smtps, http/https, etc.), but in Jok3r this 
# distinction is done by context-specific options
SERVICES_SHODAN_TO_JOKER = {
    'http-simple-new' : 'http',
    'https-simple-new': 'http',
    'udpxy'           : 'http',
    'ajp13'           : 'ajp',
    'dns-udp'         : 'dns',
    'ftp-agent'       : 'ftp',
    'ftp-proxy'       : 'ftp',
    'ftps'            : 'ftp',
    'microsoft-ds'    : 'smb',
    'ms-sql2000'      : 'mssql',
    'ms-sql-m'        : 'mssql',
    'ms-sql-s'        : 'mssql',
    'ms-wbt-server'   : 'rdp',
    'rmiregistry'     : 'java-rmi',
    'http-alt'        : 'http',
    'http-mgmt'       : 'http',
    'http-proxy'      : 'http',
    'http-wmap'       : 'http',
    'https'           : 'http',
    'https-alt'       : 'http',
    'https-wmap'      : 'http',
    'http-simple-new' : 'http',
    'ssl/http'        : 'http',
    'oracle-tns'      : 'oracle', 
    'smtps'           : 'smtp',
}  
  