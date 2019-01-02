# -*- coding: utf-8 -*-
###
### SmartModules > SmartModule (abstract class)
###
#
# Methods for commands outputs post-check processing:
# ---------------------------------------------------
#
# method(cmd_output):
# Inputs:
#   - cmd_output: Output (string) returned by the command (from the check that has been run)
#
# Output:
#   Object SmartModuleResult
#

class SmartModule:

    def __init__(self, service_name, services_config):
        self.service = service_name
        self.service_config = services_config[service_name]
        self.supported_list_options = self.service_config['supported_list_options']
        self.auth_types = self.service_config['auth_types']

    def start(self, arguments):
        pass

    def get_list_postcheck_methods(self):
        list_methods = [method_name for method_name in dir(self) if callable(getattr(self, method_name))]
        if 'start' in list_methods:
            list_methods.remove('start')
        return list_methods

    def get_postcheck_method(self, method_name):
        return getattr(self, method_name) if self.is_valid_postcheck_method(method_name) else None

    def is_valid_postcheck_method(self, method_name):
        return method_name in self.get_list_postcheck_methods()




