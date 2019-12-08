#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Command Output REST API
###
import io
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.CommandOutputsRequester import CommandOutputsRequester
from lib.webui.api.Api import api
from lib.webui.api.Models import CommandOutput
from lib.webui.api.Serializers import command_output


ns = api.namespace('command_outputs', description='Operations related to command outputs')


@ns.route('/<int:id>')
class CommandOutputsAPI(Resource):

    @ns.doc('get_command_output')
    @ns.marshal_with(command_output)
    def get(self, id):
        """Get a command output from id"""
        services_req = CommandOutputsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.COMMAND_OUTPUT_ID))
        services_req.add_filter(filter_)
        c = services_req.get_first_result()   
        if c:
            return CommandOutput(c)
        else:
            raise ApiNoResultFound()    

