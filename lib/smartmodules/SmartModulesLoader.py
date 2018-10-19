# -*- coding: utf-8 -*-
###
### SmartModules > Smart Modules Loader
###
import os
import glob
import importlib

from lib.core.Config import *
from lib.output.Logger import logger


class SmartModulesLoader:

    def __init__(self, sqlsess, services_config):
        self.sqlsess = sqlsess
        self.list_mods = list()
        
        for file in glob.glob(os.path.join(os.path.dirname(__file__), '*.py')):
            mod_name = os.path.basename(file)[:-3]
            if not mod_name.startswith('__') and not mod_name.startswith('SmartModule'):
                #mod = __import__(mod_name, globals(), locals())
                module = importlib.import_module('lib.smartmodules.'+mod_name)
                # Instantiate module and store instances in list
                self.list_mods.append(getattr(module, mod_name)(services_config))


    def __get_smartmodule(self, service):
        mod = list(filter(lambda x: x.service == service, self.list_mods))
        return mod[0] if mod else None


    def call_start_method(self, service):
        mod = self.__get_smartmodule(service.name)
        if not mod:
            return False

        logger.smartinfo('Running initialization method...')
        result = mod.start(service)
        if result:
            result.update_service(service)
            self.sqlsess.commit()
        return True


    def call_postcheck_method(self, method_name, service, cmd_output):
        """
        :param service: Service object
        """
        mod = self.__get_smartmodule(service.name)
        if not mod or not mod.is_valid_postcheck_method(method_name):
            return False
        method = mod.get_postcheck_method(method_name)

        logger.smartinfo('Running post-check method "{method}" ...'.format(method=method_name))
        result = method(cmd_output)
        if result:
            result.update_service(service)
            self.sqlsess.commit()
        return True


#loader = SmartModulesLoader()
#loader.callMethod('http', 'testMethod3', None)