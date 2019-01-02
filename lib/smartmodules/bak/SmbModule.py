# -*- coding: utf-8 -*-
###
### SmartModules > Smb Module
###
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.output.Logger import logger


class SmbModule(SmartModule):

    def __init__(self, services_config):
        super(SmbModule, self).__init__('smb', services_config)


    def start(self, service): 
        pass

    def nmap_detect_vulns(self, cmd_output):
        r = SmartModuleResult()

        if re.search('Microsoft Windows system vulnerable to remote code execution \(MS08-067\)\s*(\r\n|\r|\n)\|\s*State: VULNERABLE', 
                     cmd_output, re.IGNORECASE):
            r.add_option('vuln-ms08-067', 'true')

        if re.search('Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)\s*(\r\n|\r|\n)\|\s*State: VULNERABLE',
                     cmd_output, re.IGNORECASE):
            r.add_option('vuln-ms17-010', 'true')

        if re.search('SAMBA Remote Code Execution from Writable Share\s*(\r\n|\r|\n)\|\s*State: VULNERABLE', cmd_output, re.IGNORECASE):
            r.add_option('vuln-sambacry', 'true')

        return r

    def metasploit_detect_vulns(self, cmd_output):
        r = SmartModuleResult()

        if 'VULNERABLE to MS17-010' in cmd_output:
            r.add_option('vuln-ms17-010', 'true')

        return r


