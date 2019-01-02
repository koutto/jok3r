# -*- coding: utf-8 -*-
###
### SmartModules > Ssh Module
###
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.output.Logger import logger


class SshModule(SmartModule):

    def __init__(self, services_config):
        super(SshModule, self).__init__('ssh', services_config)


    def start(self, service): 
        pass

    def osueta_valid_usernames(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('\[\+\] User: (\S+) exists', cmd_output)
        if m:
            for username in m:
                r.add_username(username)
        return r

    def patator_valid_creds(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('[0-9]+ \| (\S+):(\S*)\s+\|', cmd_output)
        if m:
            for username, password in m:
                r.add_credentials(username, password)
        return r