#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Jobs REST API
###
import os
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.db.Job import Job
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.ServicesRequester import ServicesRequester
from lib.webui.api.Api import api, settings, jobmanager
from lib.webui.api.Models import Service
from lib.webui.api.Models import Job as JobRestModel
from lib.webui.api.Serializers import job


ns = api.namespace('jobs', description='Operations related to jobs')


@ns.route('/')
class JobListAPI(Resource):

    @ns.doc('list_jobs')
    @ns.marshal_list_with(job)
    def get(self):
        """List all jobs"""
        jobs = Session.query(Job).order_by(Job.id.desc()).all()
        return list(map(lambda x: JobRestModel(x), jobs))


    @ns.doc('create_job')
    @ns.expect(job)
    @ns.marshal_with(job, code=201)
    def post(self):
        """Create a new job"""
        if 'service_id' not in request.json or not request.json['service_id']:
            raise ApiException('No target service identifier has been provided')

        # Check existence of target service
        services_req = ServicesRequester(Session)
        filter_ = Filter()
        filter_.add_condition(
            Condition(request.json['service_id'], FilterData.SERVICE_ID)
        )
        services_req.add_filter(filter_)
        s = services_req.get_first_result()   
        if not s:
            raise ApiException('Target service provided does not exist in database')

        # Put job default configuration for undefined parameters
        if (
            'nmap_banner_grabbing' not in request.json or 
            request.json['nmap_banner_grabbing'] is None
        ):
            request.json['nmap_banner_grabbing'] = False
        if (
            'web_techno_detection' not in request.json or 
            request.json['web_techno_detection'] is None
        ):
            request.json['web_techno_detection'] = False
        if (
            'force_recheck' not in request.json or 
            request.json['force_recheck'] is None
        ):
            request.json['force_recheck'] = False
        if (
            'debug_mode' not in request.json or 
            request.json['debug_mode'] is None
        ):
            request.json['debug_mode'] = False
        if (
            'fast_mode' not in request.json or 
            request.json['fast_mode'] is None
        ):
            request.json['fast_mode'] = True


        # Create new job
        job = jobmanager.create_job(
            target_service_id=int(request.json['service_id']),
            nmap_banner_grabbing=request.json['nmap_banner_grabbing'],
            force_recheck=request.json['force_recheck'],
            fast_mode=request.json['fast_mode'],
            debug_mode=request.json['debug_mode'],
            attack_profile=request.json['attack_profile'],
            checks_selection=request.json['checks_selection'],
            categories_only=request.json['categories_only'],
            categories_exclude=request.json['categories_exclude'],
            wordlist_users=request.json['wordlist_users'],
            wordlist_passwords=request.json['wordlist_passwords']
        )

        return JobRestModel(job)


# @ns.route('/<int:id>')
# class JobAPI(Resource):

#     @ns.doc('get_mission')
#     @ns.marshal_with(mission)
#     def get(self, id):
#         """Get a mission"""
#         missions_req = MissionsRequester(Session)
#         filter_ = Filter()
#         filter_.add_condition(Condition(id, FilterData.MISSION_ID))
#         missions_req.add_filter(filter_)
#         m = missions_req.get_first_result()   
#         if m:
#             return Mission(m)
#         else:
#             raise ApiNoResultFound()


#     @ns.doc('update_mission')
#     @ns.expect(mission)
#     @ns.marshal_with(mission, code=201)
#     def put(self, id):
#         """Update a mission name or comment"""
#         missions_req = MissionsRequester(Session)
#         filter_ = Filter()
#         filter_.add_condition(Condition(id, FilterData.MISSION_ID))
#         missions_req.add_filter(filter_)
#         m = missions_req.get_first_result()   
#         if m:
#             # Rename mission
#             if 'name' in request.json:
#                 if request.json['name'] != m.name:
#                     if not missions_req.rename(m.name, request.json['name']):
#                         raise ApiException('An error occured when trying to rename ' \
#                             'mission "{name}"'.format(name=m.name))

#             # Edit comment
#             if 'comment' in request.json:
#                 if request.json['comment'] != m.comment:
#                     if not missions_req.edit_comment(request.json['comment']):
#                         raise ApiException('An error occured when trying to edit ' \
#                             'comment for mission "{name}"'.format(name=m.name))
#             return Mission(m)
#         else:
#             raise ApiNoResultFound()


#     @ns.doc('delete_mission')
#     def delete(self, id):
#         """Delete a mission"""
#         missions_req = MissionsRequester(Session)
#         filter_ = Filter()
#         filter_.add_condition(Condition(id, FilterData.MISSION_ID))
#         missions_req.add_filter(filter_)
#         m = missions_req.get_first_result()
#         if m:
#             if m.name == 'default':
#                 raise ApiException('Cannot delete "default" mission')

#             elif missions_req.delete():
#                 return None, 201
#             else:
#                 raise ApiException('An error occured when trying to delete mission ' \
#                     '"{name}"'.format(name=m.name))
#         else:
#             raise ApiNoResultFound()         


# @ns.route('/<int:id>/hosts')
# class MissionHostsAPI(Resource):

#     @ns.doc('list_hosts_in_mission')
#     @ns.marshal_with(mission_with_hosts)
#     def get(self, id):
#         """List all hosts in a mission"""
#         missions_req = MissionsRequester(Session)
#         filter_ = Filter()
#         filter_.add_condition(Condition(id, FilterData.MISSION_ID))
#         missions_req.add_filter(filter_)
#         m = missions_req.get_first_result()   
#         if m:
#             m = Mission(m)
#             m.hosts = list(map(lambda x: Host(x), m.hosts))
#             return m
#         else:
#             raise ApiNoResultFound()
