#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Info Controller
###
from lib.controller.Controller import Controller


class InfoController(Controller):

    def run(self):

        # --services
        if self.arguments.args.show_services:
            self.settings.services.show_services(self.settings.toolbox)

        # --checks
        elif self.arguments.args.show_checks:
            svc = self.arguments.args.show_checks
            self.settings.services.get_service_checks(svc).show()

        # --attack-profiles [<service>]
        elif self.arguments.args.show_attack_profiles:
            svc = self.arguments.args.show_attack_profiles
            self.settings.attack_profiles.show(None if svc=='all' else svc)

        # --options
        elif self.arguments.args.show_specific_options:
            self.settings.services.show_specific_options()

        # --products
        elif self.arguments.args.show_products:
            self.settings.services.show_products()

        # --http-auth-types
        elif self.arguments.args.show_http_auth_types:
            self.settings.services.show_authentication_types()

