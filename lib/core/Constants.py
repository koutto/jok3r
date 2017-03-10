from colorama import *

SETTINGS_DIR = 'settings'
SETTINGS_PRINT_ENABLED = True
TOOLBOX_DIR = 'toolbox'
DEFAULT_OUTPUT_DIR = 'output'
ARGPARSE_MAX_WIDTH = 100
ARGPARSE_MAX_HELP_POSITION = 40
CURRENT_VERSION = 'Version 1.0'
BANNER = Style.BRIGHT + Fore.GREEN + """
         ____.       __    ________        
        |    | ____ |  | __\_____  \______ 
        |    |/  _ \|  |/ /  _(__  <_  __ \ 
    /\__|    (  (_) )    <  /       \  | \/
    \________|\____/|__|_ \/______  /__|      {0}
                         \/       \/     
    
        --[ Hacking Arsenal Manager ]--
""".format(CURRENT_VERSION) + Style.RESET_ALL

CONF_EXT = '.conf'
MANDATORY_TOOL_OPTIONS  = ( 'name', 'category', 'description', 'command')
SPECIFIC_TOOL_OPTIONS   = { 'http': {'server': 'server_list',
						  		  'techno': 'techno_list',
						  		  'cms'   : 'cms_list',
						 		  'ssl'   : ''},
				  		    'ftp' : {} 
				 	 	  }

PROTOCOL = { 'http':    'tcp',
             'ftp':     'tcp' }