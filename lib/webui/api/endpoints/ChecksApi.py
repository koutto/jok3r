#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Security Checks REST API
###
import os
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.webui.api.Api import api, settings
from lib.webui.api.Serializers import checks_with_supported_services

ns = api.namespace('checks', description='Operations related to security checks')


@ns.route('/')
class CheckListAPI(Resource):

    @ns.doc('list_checks')
    @ns.marshal_list_with(checks_with_supported_services)
    def get(self):
        """List all security checks"""
        services_config = settings.services
        list_services = services_config.list_services(multi=False)
        list_attack_profiles = list()
        for attack_profile in settings.attack_profiles.profiles:
            list_attack_profiles.append({
                'name': attack_profile.name,
                'description': attack_profile.description,
            })
        list_checks = list()

        for service in list_services:
            service_checks = services_config.get_service_checks(service)
            if service_checks:
                for cat, checks in service_checks.checks.items():
                    for c in checks:
                        check = {
                            'check_name': c.name,
                            'category': c.category,
                            'service': service,
                            'description': c.description,
                            'tool': c.tool.name,
                            'nb_commands': len(c.commands),
                            'attack_profiles': settings.attack_profiles.\
                                get_profiles_for_check(service, c.name),
                        }
                        list_checks.append(check)

        return {
            'services': list_services,
            'attack_profiles': list_attack_profiles,
            'checks': list_checks,
            'categories': list(settings.list_all_categories()),
        }



