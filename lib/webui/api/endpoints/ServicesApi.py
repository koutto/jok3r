#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Services REST API
###
import io
from flask import request, send_file
from flask_restplus import Resource
from PIL import Image

from lib.db.Session import Session
from lib.db.Screenshot import ScreenStatus
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.ServicesRequester import ServicesRequester
from lib.webui.api.Api import api
from lib.webui.api.Models import Service
from lib.webui.api.Serializers import service


ns = api.namespace('services', description='Operations related to services')


@ns.route('/<int:id>')
class ServiceAPI(Resource):

    @ns.doc('get_service')
    @ns.marshal_with(service)
    def get(self, id):
        """Return a service"""
        services_req = ServicesRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.SERVICE_ID))
        services_req.add_filter(filter_)
        s = services_req.get_first_result()   
        if s:
            return Service(s)
        else:
            raise ApiNoResultFound()


    @ns.doc('update_service')
    @ns.expect(service)
    @ns.marshal_with(service, code=201)
    def put(self, id):
        """Update a service comment"""
        services_req = ServicesRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.SERVICE_ID))
        services_req.add_filter(filter_)
        s = services_req.get_first_result()   
        if s:
            if 'comment' in request.json:
                if request.json['comment'] != s.comment:
                    if not services_req.edit_comment(request.json['comment']):
                        raise ApiException('An error occured when trying to edit ' \
                            'comment for service')

            return Service(s)
        else:
            raise ApiNoResultFound()


    @ns.doc('delete_service')
    def delete(self, id):
        """Delete a service"""
        services_req = ServicesRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.SERVICE_ID))
        services_req.add_filter(filter_)
        s = services_req.get_first_result()   
        if s:
            if services_req.delete():
                return None, 201
            else:
                raise ApiException('An error occured when trying to delete service')
        else:
            raise ApiNoResultFound()     


@ns.route('/<int:id>/screenshot/<string:size>')
class ServiceScreenshotAPI(Resource):

    @ns.doc('get_screenshot')
    @ns.response(200, description='Web screenshot')
    @ns.produces(['image/png'])
    def get(self, id, size):
        """Get a screenshot for an HTTP service"""
        services_req = ServicesRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.SERVICE_ID))
        services_req.add_filter(filter_)
        s = services_req.get_first_result() 

        if s:
            if s.name != 'http':
                raise ApiException('Service with id {id} is not HTTP service'.format(
                    id=s.id))
            elif s.screenshot is None or s.screenshot.status != ScreenStatus.OK:
                raise ApiException('There is no screenshot for service {id}'.format(
                    id=s.id))

            if size == 'large':
                image = io.BytesIO(s.screenshot.image)
            elif size == 'thumb':
                image = io.BytesIO(s.screenshot.thumbnail)
            else:
                raise ApiException('Invalid size parameter. Supported values are: ' \
                    'large / thumb')

            # response = make_response(image)
            # response.headers.set('Content-Type', 'image/png')
            # response.headers.set('Content-Disposition', 'attachment', 
            #     filename='screenshot-{id}-{size}.png'.format(id=s.id, size=size))
            # return response 
            return send_file(
                image,
                mimetype='image/png',
                #as_attachment=True,
                attachment_filename='screenshot-{id}-{size}.png'.format(id=s.id, size=size))

        else:
            raise ApiNoResultFound()