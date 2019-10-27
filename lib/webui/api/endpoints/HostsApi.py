#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Hosts REST API
###
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.db.Service import Protocol
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.HostsRequester import HostsRequester
from lib.webui.api.Api import api
from lib.webui.api.Models import Host, Service
from lib.webui.api.Serializers import host, host_with_services

ns = api.namespace('hosts', description='Operations related to hosts')


@ns.route('/')
class HostListAPI(Resource):

    @ns.doc('list_hosts')
    @ns.marshal_list_with(host)
    def get(self):
        """List all hosts from all missions"""
        hosts = HostsRequester(Session).get_results()
        return list(map(lambda x: Host(x), hosts))


@ns.route('/<int:id>')
class HostAPI(Resource):

    @ns.doc('get_host_with_services')
    @ns.marshal_with(host_with_services)
    def get(self, id):
        """Return a host with its services"""
        hosts_req = HostsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.HOST_ID))
        hosts_req.add_filter(filter_)
        h = hosts_req.get_first_result()   
        if h:
            return Host(h)
        else:
            raise ApiNoResultFound()


    @ns.doc('update_host')
    @ns.expect(host)
    @ns.marshal_with(host, code=201)
    def put(self, id):
        """Update a host comment"""
        hosts_req = HostsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.HOST_ID))
        hosts_req.add_filter(filter_)
        h = hosts_req.get_first_result()   
        if h:
            if 'comment' in request.json:
                if request.json['comment'] != h.comment:
                    if not hosts_req.edit_comment(request.json['comment']):
                        raise ApiException('An error occured when trying to edit ' \
                            'comment for host "{ip}"'.format(name=h.ip))
            return Host(h)
        else:
            raise ApiNoResultFound()


    @ns.doc('delete_host')
    def delete(self, id):
        """Delete a host with its services"""
        hosts_req = HostsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.HOST_ID))
        hosts_req.add_filter(filter_)
        h = hosts_req.get_first_result()   
        if h:
            if hosts_req.delete():
                return None, 201
            else:
                raise ApiException('An error occured when trying to delete host ' \
                    '"{ip}" with its services'.format(ip=h.ip))
        else:
            raise ApiNoResultFound()      


@ns.route('/<int:id>/services')
class HostServicesAPI(Resource):

    @ns.doc('list_services_in_host')
    @ns.marshal_with(host_with_services)
    def get(self, id):
        """List all services for a host"""
        hosts_req = HostsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.HOST_ID))
        hosts_req.add_filter(filter_)
        h = hosts_req.get_first_result()    
        if h:
            h = Host(h)
            h.services = list(map(lambda x: Service(x), h.services))
            return h

        else:
            raise ApiNoResultFound()