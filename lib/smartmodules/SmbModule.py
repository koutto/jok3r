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

        if re.search('Microsoft Windows system vulnerable to remote code execution \(MS08-067\)\s*(\r\n|\r|\n)\|\s*State: VULNERABLE', cmd_output):
            r.add_option('vuln-ms01-067', 'true')
        return r

