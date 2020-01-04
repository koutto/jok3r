#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Hosts
###
from lib.requester.Requester import Requester
from lib.utils.StringUtils import StringUtils
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Service import Service, Protocol
from lib.requester.JobsRequester import JobsRequester
from lib.screenshoter.ScreenshotsProcessor import ScreenshotsProcessor
from lib.output.Logger import logger
from lib.output.Output import Output


class HostsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Host).join(Mission)
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def show(self):
        """Display selected hosts"""
        results = self.get_results()

        if not results:
            logger.warning('No host to display')
        else:
            data = list()
            columns = [
                'IP',
                'Hostname',
                'OS',
                'Type',
                'Vendor',
                'Comment',
                'TCP',
                'UDP',
            ]
            for r in results:
                data.append([
                    r.ip,
                    StringUtils.wrap(r.hostname, 45) if r.hostname != str(r.ip) else '',
                    StringUtils.wrap(r.os, 50),
                    r.type,
                    StringUtils.wrap(r.vendor, 30),
                    StringUtils.shorten(r.comment, 40),
                    r.get_nb_services(Protocol.TCP),
                    r.get_nb_services(Protocol.UDP),       
                ])
            Output.table(columns, data, hrules=False)


    #------------------------------------------------------------------------------------
    
    def add_or_merge_host(self, host, take_screenshot=True):
        """
        Add/merge new host into the current mission scope in database.
        :param Host host: Host to add (or merge with matching existing one)
        """
        match_host = self.sqlsess.query(Host).join(Mission)\
                           .filter(Mission.name == self.current_mission)\
                           .filter(Host.ip == host.ip).first()

        # If host already exists in db, update its info and add/merge services 
        # for this host
        if match_host:
            match_host.merge(host)
            logger.success('Updated host: {ip} {hostname}'.format(
                ip       = host.ip,
                hostname = '('+host.hostname+')' if host.hostname else ''))

            for service in host.services:
                match_service = self.sqlsess.query(Service)\
                                    .join(Host)\
                                    .join(Mission)\
                                    .filter(Host.ip == service.host.ip)\
                                    .filter(Mission.name == self.current_mission)\
                                    .filter(Service.name == service.name)\
                                    .filter(Service.port == service.port)\
                                    .filter(Service.protocol == service.protocol)\
                                    .filter(Service.url == service.url).first()
                if match_service:
                    match_service.merge(service)
                else:
                    service.host = match_host
                    self.sqlsess.add(service)

                    if service.name == 'http' and take_screenshot:
                        processor = ScreenshotsProcessor(
                            self.current_mission, 
                            self.sqlsess
                        )
                        if processor is not None:
                            processor.take_screenshot(service)

                logger.success('{action} service: host {ip} | port {port}/{proto} | ' \
                    'service {service}'.format(
                    action  = 'Updated' if match_service else 'Added',
                    ip      = service.host.ip,
                    port    = service.port,
                    proto   = { Protocol.TCP: 'tcp', Protocol.UDP: 'udp' }.get(
                        service.protocol),
                    service = service.name))

        # If new host, add it in db
        else:
            # Add the host in the current mission
            mission = self.sqlsess.query(Mission)\
                          .filter(Mission.name == self.current_mission).first()
            host.mission = mission
            
            self.sqlsess.add(host) # add host and its service
            logger.success('Added host: {ip} {hostname}'.format(
                ip       = host.ip,
                hostname = '('+host.hostname+')' if host.hostname else ''))

            for service in host.services:
                logger.success('Added service: host {ip} | port {port}/{proto} | ' \
                    'service {service}'.format(
                    ip      = service.host.ip,
                    port    = service.port,
                    proto   = { Protocol.TCP: 'tcp', Protocol.UDP: 'udp' }.get(
                        service.protocol),
                    service = service.name))
                if service.name == 'http' and take_screenshot:
                    processor = ScreenshotsProcessor(
                        self.current_mission, 
                        self.sqlsess
                    )
                    if processor is not None:
                        processor.take_screenshot(service)

        self.sqlsess.commit()


    #------------------------------------------------------------------------------------

    def edit_comment(self, comment):
        """
        Edit comment of selected hosts.
        :param str comment: New comment
        :return: Status
        :rtype: bool
        """
        results = self.get_results()
        if not results:
            logger.error('No matching host')
            return False
        else:
            for r in results:
                r.comment = comment
            self.sqlsess.commit()
            logger.success('Comment edited')
            return True


    def delete(self):
        """
        Delete selected hosts
        :return: Status
        :rtype: bool
        """
        results = self.get_results()
        if not results:
            logger.error('No matching host')
            return False
        else:
            jobs_req = JobsRequester(self.sqlsess)
            for r in results:
                # Host cannot be deleted if it has one (or more) queued/running
                # jobs currently targeting one of its service
                if jobs_req.is_host_with_queued_or_running_jobs(r.id):
                    logger.error('Host {ip} {hostname} cannot be deleted because ' \
                        'there is a queued or running job currently targeting ' \
                        'it'.format(
                            ip=r.ip, 
                            hostname='('+r.hostname+')' if r.hostname else '', 
                        )
                    )
                    continue

                logger.info('Host {ip} {hostname} (and its {nb_services} services) ' \
                    'deleted'.format(
                    ip=r.ip, 
                    hostname='('+r.hostname+')' if r.hostname else '', 
                    nb_services=len(r.services)))
                self.sqlsess.delete(r)

            self.sqlsess.commit()
            return True


    #------------------------------------------------------------------------------------

    def order_by(self, column):
        """
        Add ORDER BY statement
        :param str column: Column name to order by
        """
        mapping = {
            'ip'       : Host.ip,
            'hostname' : Host.hostname,
            'os'       : Host.os,
            'type'     : Host.type,
            'vendor'   : Host.vendor,
            'comment'  : Host.comment,
        }
        
        if column.lower() not in mapping.keys():
            logger.warning('Ordering by column {col} is not supported'.format(
                col=column.lower()))
            return

        super().order_by(mapping[column.lower()])



             