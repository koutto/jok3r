#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Tools REST API
###
import os
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.webui.api.Api import api, settings
from lib.webui.api.Serializers import tool

ns = api.namespace('tools', description='Operations related to toolbox')


@ns.route('/')
class ToolListAPI(Resource):

    @ns.doc('list_tools')
    @ns.marshal_list_with(tool)
    def get(self):
        """List all tools in toolbox"""
        toolbox = settings.toolbox
        services = list(settings.services.keys())
        services.sort()
        list_tools = list()

        for service in services:
            for t in toolbox[service]:
                t = {
                    'tool_name': t.name,
                    'target_service': t.target_service,
                    'is_installed': t.installed,
                    'last_update': t.last_update,
                    'description': t.description,
                }
                list_tools.append(t)

        return list_tools



