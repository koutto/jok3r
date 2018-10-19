# -*- coding: utf-8 -*-
###
### Requester > Hosts
###
from lib.requester.Requester import Requester
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger
from lib.output.Output import Output


class HostsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Host).join(Mission)
        super().__init__(sqlsession, query)

    def show(self):
        results = self.get_results()

        if not results:
            logger.warning('No host to display')
        else:
            data = list()
            columns = [
                'IP',
                'Hostname',
                'OS',
                'Comment',
                '# Services',
            ]
            for r in results:
                data.append([
                    r.ip,
                    r.hostname,
                    r.os,
                    r.comment,
                    len(r.services)          
                ])
            Output.table(columns, data, hrules=False)


    def edit_comment(self, comment):
        results = self.get_results()
        if not results:
            logger.error('No matching host')
        else:
            for r in results:
                r.comment = comment
            self.sqlsess.commit()
            logger.success('Comment edited')


    def delete(self):
        results = self.get_results()
        if not results:
            logger.error('No matching host')
        else:
            for r in results:
                logger.info('Host {ip} {hostname} (and its {nb_services} services) deleted'.format(
                    ip=r.ip, 
                    hostname='('+r.hostname+')' if r.hostname else '', 
                    nb_services=len(r.services)))
                self.sqlsess.delete(r)
            self.sqlsess.commit()


    def order_by(self, column):
        mapping = {
            'ip'       : Host.ip,
            'hostname' : Host.hostname,
            'os'       : Host.os,
            'comment'  : Host.comment,
        }
        if column.lower() not in mapping.keys():
            logger.warning('Ordering by column {col} is not supported'.format(col=column.lower()))
            return
        super().order_by(mapping[column.lower()])


    def add_or_merge_host(self, host):
        match_host = self.sqlsess.query(Host).join(Mission)\
                           .filter(Mission.name == self.current_mission)\
                           .filter(Host.ip == host.ip).first()

        # If host already exists in db, update its info and add/merge services for this host
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

                logger.success('{action} service: host {ip} | port {port}/{proto} | service {service}'.format(
                    action  = 'Updated' if match_service else 'Added',
                    ip      = service.host.ip,
                    port    = service.port,
                    proto   = { Protocol.TCP: 'tcp', Protocol.UDP: 'udp' }.get(service.protocol),
                    service = service.name))

        # Of new host, add it in db
        else:
            # Add the host in the current mission
            mission = self.sqlsess.query(Mission).filter(Mission.name == self.current_mission).first()
            host.mission = mission
            
            self.sqlsess.add(host) # add host and its service
            logger.success('Added host: {ip} {hostname}'.format(
                ip       = host.ip,
                hostname = '('+host.hostname+')' if host.hostname else ''))

            for service in host.services:
                logger.success('Added service: host {ip} | port {port}/{proto} | service {service}'.format(
                    ip      = service.host.ip,
                    port    = service.port,
                    proto   = { Protocol.TCP: 'tcp', Protocol.UDP: 'udp' }.get(service.protocol),
                    service = service.name))
        self.sqlsess.commit()



             