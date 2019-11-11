#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Vulns REST API
###
import io
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.VulnsRequester import VulnsRequester
from lib.webui.api.Api import api
from lib.webui.api.Models import Vuln
from lib.webui.api.Serializers import vuln


ns = api.namespace('vulns', description='Operations related to vulnerabilities')


@ns.route('/<int:id>')
class VulnAPI(Resource):

    @ns.doc('get_vuln')
    @ns.marshal_with(vuln)
    def get(self, id):
        """Return a vulnerability"""
        req = VulnsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.VULN_ID))
        req.add_filter(filter_)
        v = req.get_first_result()   
        if v:
            return Vuln(v)
        else:
            raise ApiNoResultFound()


    @ns.doc('update_vuln')
    @ns.expect(vuln)
    @ns.marshal_with(vuln, code=201)
    def put(self, id):
        """Update a vulnerability"""
        if 'name' not in request.json:
            raise ApiException('Vulnerability name must be specified')
        elif not request.json['name']:
            raise ApiException('Vulnerability name cannot be empty')

        req = VulnsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.VULN_ID))
        req.add_filter(filter_)
        v = req.get_first_result()   
        if v:
            if not req.edit_vuln_name(request.json['name']):
                raise ApiException('An error occured when trying to change ' \
                    'the name of the vulnerability')

            return Vuln(v)
        else:
            raise ApiNoResultFound()


    @ns.doc('delete_vuln')
    def delete(self, id):
        """Delete a vulnerability"""
        req = VulnsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.VULN_ID))
        req.add_filter(filter_)
        v = req.get_first_result()   
        if v:
            if req.delete():
                return None, 201
            else:
                raise ApiException('An error occured when trying to delete ' \
                    'vulnerability')
        else:
            raise ApiNoResultFound()     