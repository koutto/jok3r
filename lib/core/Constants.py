from colorama import *
from lib.core.Tool import ToolType

CURRENT_VERSION = 'Version 1.1'
BANNER = Style.BRIGHT + Fore.GREEN + """
         ____.       __    ________        
        |    | ____ |  | __\_____  \______ 
        |    |/  _ \|  |/ /  _(__  <_  __ \ 
    /\__|    (  (_) )    <  /       \  | \/
    \________|\____/|__|_ \/______  /__|      {0}
                         \/       \/     
    
    --[ Network & Web Hacking Arsenal Manager ]--
""".format(CURRENT_VERSION) + Style.RESET_ALL


SETTINGS_DIR = 'settings'
SETTINGS_PRINT_ENABLED = True
TOOLBOX_DIR = 'toolbox'
DEFAULT_OUTPUT_DIR = 'output'
WORDLISTS_DIR = 'wordlists'
ARGPARSE_MAX_WIDTH = 100
ARGPARSE_MAX_HELP_POSITION = 40

CONF_EXT = '.conf'
INSTALL_STATUS_CONF_FILE = '_install_status'

MULTI_SERVICES_CONF_FILE = 'multi'
MULTI_SERVICES_TOOLBOX_SUBDIR = 'multi'

PREFIX_TOOL_SECTIONNAME = 'tool_'
PREFIX_TOOL_USEMULTI_SECTIONNAME = 'usemulti_'

MANDATORY_TOOL_OPTIONS = {  ToolType.STANDARD:          ('name', 'category', 'description', 'command'),
                            ToolType.MULTI_SERVICES:    ('name', 'description'),
                            ToolType.USE_MULTI:         ('name', 'tool_ref_name', 'category', 'description', 'command')}


SPECIFIC_TOOL_OPTIONS   = { 'http': {'server': 'server_list',
						  		     'techno': 'techno_list',
						  		     'cms'   : 'cms_list',
						 		     'ssl'   : '',
                                     'webdav': ''},
				  		    'ftp' : {'ssl'   : ''} 
				 	 	  }

PROTOCOL = { 'ftp':     'tcp', 
             'ssh':     'tcp',
             'telnet':  'tcp',
             'smtp':    'tcp',
             'http':    'tcp',
             'smb':     'tcp',
             'snmp':    'udp' }