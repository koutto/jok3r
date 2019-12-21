#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Jobs
###
from sqlalchemy import or_
from lib.requester.Requester import Requester
from lib.utils.StringUtils import StringUtils
from lib.db.Job import Job
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Service import Service
from lib.output.Logger import logger


class JobsRequester(Requester):
    def __init__(self, sqlsession):
        query = sqlsession.query(Job).join(Service).join(Host).join(Mission)
        super().__init__(sqlsession, query)

    # ------------------------------------------------------------------------------------

    def is_service_with_queued_or_running_jobs(self, service_id):
        """
        Check if a service is currently targeted in one or more job(s) with the
        "queued" or "running" status.

        :param int service_id: Service identifier
        :return: Status
        :rtype: bool
        """
        jobs = (
            self.sqlsess.query(Job)
            .filter(Job.service_id == service_id)
            .filter(or_(Job.status == 'queued', Job.status == 'running'))
            .first()
        )
        return (jobs is not None)


    def is_host_with_queued_or_running_jobs(self, host_id):
        """
        Check if a host has at least one service that is currently targeted in 
        one or more job(s) with the "queued" or "running" status.

        :param int host_id: Host identifier
        :return: Status
        :rtype: bool
        """
        host = self.sqlsess.query(Host).filter(Host.id == host_id).first()
        if not host:
            return False

        for service in host.services:
            if self.is_service_with_queued_or_running_jobs(service.id):
                return True
        return False


    def is_mission_with_queued_or_running_jobs(self, mission_id):
        """
        Check if a mission has at least one service that is currently targeted in 
        one or more job(s) with the "queued" or "running" status.

        :param int mission_id: Mission identifier
        :return: Status
        :rtype: bool
        """
        mission = self.sqlsess.query(Mission).filter(Mission.id == mission_id).first()
        if not mission:
            return False

        for host in mission.hosts:
            if self.is_host_with_queued_or_running_jobs(host.id):
                return True
        return False