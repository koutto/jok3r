# -*- coding: utf-8 -*-
###
### Core > Info Controller
###
from lib.controller.Controller import Controller


class InfoController(Controller):

    def run(self):
        if self.arguments.args.show_services:
            self.settings.services.show_services(self.settings.toolbox)
        elif self.arguments.args.show_specific_options:
            self.settings.services.show_specific_options()
        elif self.arguments.args.show_http_auth_types:
            self.settings.services.show_authentication_types('http')
        elif self.arguments.args.show_checks:
            svc = self.arguments.args.show_checks
            self.settings.services.get_service_checks(svc).show()
