#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Credentials REST API
###
import io
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.CredentialsRequester import CredentialsRequester
from lib.webui.api.Api import api
from lib.webui.api.Models import Credential
from lib.webui.api.Serializers import credential


ns = api.namespace('credentials', description='Operations related to credentials')



@ns.route('/')
class CredentialListAPI(Resource):

    @ns.doc('add_credential')
    @ns.expect(credential)
    @ns.marshal_with(credential, code=201)
    def post(self):
        """Add a credential to a service"""
        if 'service_id' not in request.json:
            raise ApiException('Wrong request, missing service identifier')
        if 'username' not in request.json:
            raise ApiException('Username must be specified')
        if 'password' not in request.json:
            request.json['password'] = None
        if 'type' not in request.json:
            request.json['type'] = None
        if 'type' in request.json and request.json['type'] is not None \
            and len(request.json['type']) == 0:
            request.json['type'] = None

        req = CredentialsRequester(Session)
        new_cred = req.add_cred(
            request.json['service_id'],
            request.json['username'],
            request.json['password'],
            request.json['type'])
        
        if new_cred:
            return Credential(new_cred)
        else:
            raise ApiException('An error occured, unable to add new credential')


@ns.route('/<int:id>')
class CredentialAPI(Resource):

    @ns.doc('get_credential')
    @ns.marshal_with(credential)
    def get(self, id):
        """Return a credential"""
        req = CredentialsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.CREDENTIAL_ID))
        req.add_filter(filter_)
        c = req.get_first_result()   
        if c:
            return Credential(c)
        else:
            raise ApiNoResultFound()


    @ns.doc('update_credential')
    @ns.expect(credential)
    @ns.marshal_with(credential, code=201)
    def put(self, id):
        """Update a credential"""
        if 'username' not in request.json:
            raise ApiException('Username must be specified')
        if 'password' not in request.json:
            request.json['password'] = None
        if 'type' not in request.json:
            request.json['type'] = None
        if 'type' in request.json and request.json['type'] is not None \
            and len(request.json['type']) == 0:
            request.json['type'] = None
        if 'comment' not in request.json:
            request.json['comment'] = ''

        req = CredentialsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.CREDENTIAL_ID))
        req.add_filter(filter_)
        c = req.get_first_result()   
        if c:
            edited_cred = req.edit_cred(
                request.json['username'],
                request.json['password'],
                request.json['comment'],
                request.json['type'])

            if edited_cred:
                return Credential(edited_cred)
            else:
                raise ApiException('An error occured, unabled to edit credential')
        else:
            raise ApiNoResultFound()


    @ns.doc('delete_credential')
    def delete(self, id):
        """Delete a credential"""
        req = CredentialsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.CREDENTIAL_ID))
        req.add_filter(filter_)
        c = req.get_first_result()   
        if c:
            if req.delete():
                return None, 201
            else:
                raise ApiException('An error occured when trying to delete ' \
                    'credential')
        else:
            raise ApiNoResultFound()     