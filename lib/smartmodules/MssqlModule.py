# -*- coding: utf-8 -*-
###
### SmartModules > Mssql Module
###
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.output.Logger import logger


class MssqlModule(SmartModule):

    def __init__(self, services_config):
        super(MssqlModule, self).__init__('mssql', services_config)


    def start(self, service): 
        pass

    def msdat_valid_creds(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('Valid credential: \'(\S+)\'/\'(\S+)\'', cmd_output)
        if m:
            for username, password in m:
                r.add_credentials(username, password)
        return r