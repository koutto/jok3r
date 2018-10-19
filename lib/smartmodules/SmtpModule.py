# -*- coding: utf-8 -*-
###
### SmartModules > Smtp Module
###
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.output.Logger import logger


class SmtpModule(SmartModule):

    def __init__(self, services_config):
        super(SmtpModule, self).__init__('smtp', services_config)


    def start(self, service): 
        pass

    def smtpuserenum_valid_users(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall(': (\S+) exists', cmd_output)
        if m:
            for username in m:
                r.add_username(username)
        return r