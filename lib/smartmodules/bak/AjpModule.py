# -*- coding: utf-8 -*-
###
### SmartModules > Ajp Module
###
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.output.Logger import logger


class AjpModule(SmartModule):

    def __init__(self, services_config):
        super(AjpModule, self).__init__('ajp', services_config)


    def start(self, service): 
        pass

    def ajpy_valid_creds(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('Found valid credz: (\S+):(\S*)', cmd_output)
        if m:
            for username, password in m:
                r.add_credentials(username, password)
        return r

