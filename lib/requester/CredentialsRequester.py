#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Credentials
###
from lib.requester.Requester import Requester
from lib.utils.StringUtils import StringUtils
from lib.db.Credential import Credential
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger
from lib.output.Output import Output


class CredentialsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Credential).join(Service).join(Host).join(Mission)  
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def show(self):
        """Display selected credentials"""
        results = self.get_results()

        if not results:
            logger.warning('No credential to display')
        else:
            data = list()
            columns = [
                'IP',
                'Hostname',
                'Service',
                'Port',
                'Proto',
                'Type',
                'Username',
                'Password',
                'URL',
                'Comment',
            ]
            for r in results:
                data.append([
                    r.service.host.ip,
                    r.service.host.hostname \
                        if r.service.host.hostname != str(r.service.host.ip) else '',
                    r.service.name,
                    r.service.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.service.protocol),
                    r.type or '',
                    '<empty>' if r.username == '' else r.username,
                    {'': '<empty>', None: '<???>'}.get(r.password, r.password),
                    StringUtils.wrap(r.service.url, 50),
                    StringUtils.wrap(r.comment, 50),
                ])
            Output.table(columns, data, hrules=False)


    #------------------------------------------------------------------------------------

    def add_cred(self, service_id, username, password, auth_type=None):
        """
        Add new credential for a given service.
        :param int service_id: Id of service
        :param str username: Username
        :param str password: Password (None if unknown)
        :param str auth_type: Authentication type for HTTP service
        """
        cred = self.sqlsess.query(Credential).join(Service)\
                           .filter(Service.id == service_id)\
                           .filter(Credential.username == username)\
                           .filter(Credential.password == password)\
                           .filter(Credential.type == auth_type).first()
        if cred:
            logger.warning('Credential already exists in database')
        else:
            service = self.sqlsess.query(Service).filter(Service.id == service_id)\
                                  .first()
            if not service:
                logger.error('Service id {id} is invalid'.format(id=service_id))
            else:
                cred = Credential(
                    username = username,
                    password = password,
                    type     = auth_type if service.name == 'http' else None) 
                
                self.sqlsess.add(cred)
                service.credentials.append(cred)

                username = '<empty>' if username == '' else username
                password = {'': '<empty>', None: '<???>'}.get(password, password)
                auth_typ = '('+str(auth_type)+')' if auth_type else ''
                hostname = '('+service.host.hostname+')' if service.host.hostname else ''
                protocol = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                    service.protocol)

                logger.success('Credential {username}/{password}{auth_type} added ' \
                    'to service {service} host={ip}{hostname} ' \
                    'port={port}/{proto}'.format(
                    username  = username,
                    password  = password,
                    auth_type = auth_typ,
                    service   = service.name,
                    ip        = service.host.ip,
                    hostname  = hostname,
                    port      = service.port,
                    proto     = protocol))

                self.sqlsess.commit()


    #------------------------------------------------------------------------------------

    def edit_comment(self, comment):
        """
        Edit comment of selected credentials.
        :param str comment: New comment
        """
        results = self.get_results()
        if not results:
            logger.error('No matching credential')
        else:
            for r in results:
                r.comment = comment
            self.sqlsess.commit()
            logger.success('Comment edited')


    def delete(self):
        """Delete selected credentials"""
        results = self.get_results()
        if not results:
            logger.error('No matching credential')
        else:
            for r in results:
                logger.info('Credential {username}/{password} from host={ip} ' \
                    'service={service} ({port}/{proto}) deleted'.format(
                    username = r.username,
                    password = r.password,
                    ip       = r.service.host.ip,
                    service  = r.service.name,
                    port     = r.service.port,
                    proto    = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        r.service.protocol)))

                self.sqlsess.delete(r)

            self.sqlsess.commit()


    #------------------------------------------------------------------------------------

    def order_by(self, column):
        """
        Add ORDER BY statement
        :param str column: Column name to order by
        """
        mapping = {
            'ip'       : Host.ip,
            'hostname' : Host.hostname,
            'port'     : Service.port,
            'proto'    : Service.protocol,
            'type'     : Credential.type,
            'username' : Credential.username,
            'password' : Credential.password,
            'url'      : Service.url,
            'comment'  : Service.comment,
        }

        if column.lower() not in mapping.keys():
            logger.warning('Ordering by column {col} is not supported'.format(
                col=column.lower()))
            return

        super().order_by(mapping[column.lower()])


