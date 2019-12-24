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

        # Check validity of parameters
        if (
            request.json['attack_profile'] and
            not settings.attack_profiles.is_valid_profile_name(
                request.json['attack_profile'])
        ):
            raise ApiException('Invalid attack profile')

        if request.json['checks_selection']:
            for check in request.json['checks_selection'].split(','):
                if not settings.services.is_existing_check(check):
                    raise ApiException('Invalid check provided: {}'.format(check))

        if request.json['categories_only']:
            for cat in request.json['categories_only'].split(','):
                if cat not in settings.services.list_all_categories():
                    raise ApiException('Invalid category provided: {}'.format(cat))

        if request.json['categories_exclude']:
            for cat in request.json['categories_exclude'].split(','):
                if cat not in settings.services.list_all_categories():
                    raise ApiException('Invalid category provided: {}'.format(cat))

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


@ns.route('/<int:id>')
class JobAPI(Resource):

    @ns.doc('get_job')
    @ns.marshal_with(job)
    def get(self, id):
        """Get a job"""
        job = Session.query(Job).filter(Job.id == id).first()
        if job:
            return JobRestModel(job)
        else:
            raise ApiNoResultFound()


    @ns.doc('update_job')
    @ns.expect(job)
    @ns.marshal_with(job, code=201)
    def put(self, id):
        """Update a mission name or comment"""
        job = Session.query(Job).filter(Job.id == id).first()
        if job:
            # Edit comment
            if 'comment' in request.json:
                if request.json['comment'] != job.comment:
                    job.comment = request.json['comment']
                    Session.commit()
            return JobRestModel(job)
        else:
            raise ApiNoResultFound()


    @ns.doc('delete_job')
    def delete(self, id):
        """Delete a job"""
        job = Session.query(Job).filter(Job.id == id).first()
        if job:
            Session.delete(job)
            return None, 201
        else:
            raise ApiNoResultFound()    



@ns.route('/<int:id>/queue')
class JobQueueAPI(Resource):

    @ns.doc('queue_job')
    def get(self, id):
        """Queue a job"""
        job = Session.query(Job).filter(Job.id == id).first()
        if job:
            if jobmanager.queue_job(id):
                return None, 201
            else:
                raise ApiException('An error occured when trying to queue job ' \
                    '#{}'.format(id))
        else:
            raise ApiNoResultFound() 


@ns.route('/<int:id>/cancel')
class JobCancelAPI(Resource):

    @ns.doc('cancel_job')
    def get(self, id):
        """Cancel a job"""
        job = Session.query(Job).filter(Job.id == id).first()
        if job:
            if jobmanager.cancel_job(id):
                return None, 201
            else:
                raise ApiException('An error occured when trying to cancel job ' \
                    '#{}'.format(id))
        else:
            raise ApiNoResultFound() 


@ns.route('/<int:id>/stop')
class JobStopAPI(Resource):

    @ns.doc('stop_job')
    def get(self, id):
        """Stop a job"""
        job = Session.query(Job).filter(Job.id == id).first()
        if job:
            if jobmanager.stop_job(id):
                return None, 201
            else:
                raise ApiException('An error occured when trying to stop job ' \
                    '#{}'.format(id))
        else:
            raise ApiNoResultFound() 


@ns.route('/<int:id>/restart')
class JobRestartAPI(Resource):

    @ns.doc('restart_job')
    def get(self, id):
        """Restart a job"""
        job = Session.query(Job).filter(Job.id == id).first()
        if job:
            if jobmanager.restart_job(id):
                return None, 201
            else:
                raise ApiException('An error occured when trying to restart job ' \
                    '#{}'.format(id))
        else:
            raise ApiNoResultFound() 