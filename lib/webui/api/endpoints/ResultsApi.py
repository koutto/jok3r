#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Results REST API
###
import io
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.ServicesRequester import ServicesRequester
from lib.webui.api.Api import api
from lib.webui.api.Models import ServiceWithAll
from lib.webui.api.Serializers import service_with_all


ns = api.namespace('results', description='Operations related to results')


@ns.route('/<int:id>')
class ResultsAPI(Resource):

    @ns.doc('get_results')
    @ns.marshal_with(service_with_all)
    def get(self, id):
        """Get a service with its results, credentials, vulnerabilities..."""
        services_req = ServicesRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.SERVICE_ID))
        services_req.add_filter(filter_)
        s = services_req.get_first_result()   
        if s:
            return ServiceWithAll(s)
        else:
            raise ApiNoResultFound()    

