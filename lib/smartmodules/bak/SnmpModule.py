# -*- coding: utf-8 -*-
###
### SmartModules > Snmp Module
###
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.output.Logger import logger


class SnmpModule(SmartModule):

    def __init__(self, services_config):
        super(SnmpModule, self).__init__('snmp', services_config)


    def start(self, service): 
        pass

    def msf_snmp_valid_community(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('Login Successful: (\S+)', cmd_output)
        if m:
            for community in m:
                r.add_username(community)
        return r
