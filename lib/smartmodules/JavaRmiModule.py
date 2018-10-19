# -*- coding: utf-8 -*-
###
### SmartModules > Java-rmi Module
###
import re

from lib.smartmodules.SmartModule import SmartModule
from lib.smartmodules.SmartModuleResult import SmartModuleResult
from lib.core.Config import *
from lib.output.Logger import logger


class JavaRmiModule(SmartModule):

    def __init__(self, services_config):
        super(JavaRmiModule, self).__init__('java-rmi', services_config)


    def start(self, service): 
        pass

    def nmap_detect_jmx_and_rmissl(self, cmd_output):
        r = SmartModuleResult()
        if 'jmxrmi' in cmd_output:
            r.add_option('jmx', 'true')
        if 'ssl' in cmd_output:
            r.add_option('rmissl', 'true')
        return r

    def jmxbf_valid_creds(self, cmd_output):
        r = SmartModuleResult()
        m = re.findall('We got a valid connection for: (\S+):(\S*)', cmd_output)
        if m:
            for username, password in m:
                r.add_credentials(username, password)
        return r