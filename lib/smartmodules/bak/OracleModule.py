# -*- coding: utf-8 -*-
###
### SmartModules > Oracle Module
###
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.output.Logger import logger


class OracleModule(SmartModule):

    def __init__(self, services_config):
        super(OracleModule, self).__init__('oracle', services_config)


    def start(self, service): 
        pass

    def tnscmd_sid(self, cmd_output):
        r = SmartModuleResult()
        m = re.search('ALIAS=(listener_)?(?P<sid>[a-zA-Z0-9]+)\)', cmd_output)
        if m:
            r.add_option('sid', m.group('sid'))
        return r

    def odat_valid_creds(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('Valid credential: (\S+)/(\S+)', cmd_output)
        if m:
            for username, password in m:
                r.add_credentials(username, password)
        return r