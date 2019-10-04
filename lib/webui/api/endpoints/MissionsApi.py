#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Missions REST API
###
from flask import request
from flask_restplus import Resource

from lib.db.Service import Protocol
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.MissionsRequester import MissionsRequester
from lib.webui.api.Api import api, sqlsession
from lib.webui.api.Models import Mission, Host
from lib.webui.api.Serializers import mission, host, mission_with_hosts

ns = api.namespace('missions', description='Operations related to missions')


@ns.route('/')
class MissionListAPI(Resource):

    @ns.doc('list_missions')
    @ns.marshal_list_with(mission)
    def get(self):
        """List all missions"""
        missions = MissionsRequester(sqlsession).get_results()
        # missions_json = []
        # for m in missions:
        #     m_json = api.marshal(m, mission)
        #     m_json['services_count'] = m.get_nb_services()
        #     missions_json.append(m_json)
        # return missions_json
        return list(map(lambda x: Mission(x), missions))


    @ns.doc('create_mission')
    @ns.expect(mission)
    @ns.marshal_with(mission, code=201)
    def post(self):
        """Create a new mission"""
        name = request.json['name']
        missions_req = MissionsRequester(sqlsession)
        if missions_req.add(name):
            filter_ = Filter()
            filter_.add_condition(Condition(name, FilterData.MISSION_EXACT))
            missions_req.add_filter(filter_)
            m = missions_req.get_first_result()
            if m:
                return Mission(m)
            else:
                raise ApiNoResultFound()
        else:
            raise ApiException('A mission with the name "{name}" already exists'.format(
                name=name))



@ns.route('/<int:id>')
class MissionAPI(Resource):

    @ns.doc('get_mission')
    @ns.marshal_with(mission)
    def get(self, id):
        """Get a mission"""
        missions_req = MissionsRequester(sqlsession)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.MISSION_ID))
        missions_req.add_filter(filter_)
        m = missions_req.get_first_result()   
        if m:
            return Mission(m)
        else:
            raise ApiNoResultFound()


    @ns.doc('update_mission')
    @ns.expect(mission)
    @ns.marshal_with(mission, code=201)
    def put(self, id):
        """Update a mission name or comment"""
        missions_req = MissionsRequester(sqlsession)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.MISSION_ID))
        missions_req.add_filter(filter_)
        m = missions_req.get_first_result()   
        if m:
            # Rename mission
            if 'name' in request.json:
                if request.json['name'] != m.name:
                    if not missions_req.rename(m.name, request.json['name']):
                        raise ApiException('An error occured when trying to rename ' \
                            'mission "{name}"'.format(name=m.name))

            # Edit comment
            if 'comment' in request.json:
                if request.json['comment'] != m.comment:
                    if not missions_req.edit_comment(request.json['comment']):
                        raise ApiException('An error occured when trying to edit ' \
                            'comment for mission "{name}"'.format(name=m.name))
            return Mission(m)
        else:
            raise ApiNoResultFound()


    @ns.doc('delete_mission')
    def delete(self, id):
        """Delete a mission"""
        missions_req = MissionsRequester(sqlsession)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.MISSION_ID))
        missions_req.add_filter(filter_)
        m = missions_req.get_first_result()
        if m:
            if missions_req.delete():
                return None, 201
            else:
                raise ApiException('An error occured when trying to delete mission ' \
                    '"{name}"'.format(name=m.name))
        else:
            raise ApiNoResultFound()         


@ns.route('/<int:id>/hosts')
class MissionHostsAPI(Resource):

    @ns.doc('list_hosts_in_mission')
    @ns.marshal_with(mission_with_hosts)
    def get(self, id):
        """List all hosts in a mission"""
        missions_req = MissionsRequester(sqlsession)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.MISSION_ID))
        missions_req.add_filter(filter_)
        m = missions_req.get_first_result()   
        if m:
            m = Mission(m)
            m.hosts = list(map(lambda x: Host(x), m.hosts))
            return m

        else:
            raise ApiNoResultFound()
