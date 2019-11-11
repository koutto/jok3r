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
                username = '<empty>' if r.username == '' else r.username
                username = Output.colored(username, color='green' if \
                    r.password is not None else 'yellow')
                password = {'': '<empty>', None: '<???>'}.get(r.password, r.password)
                password = Output.colored(password, color='green' if \
                    r.password is not None else 'yellow')

                data.append([
                    r.service.host.ip,
                    r.service.host.hostname \
                        if r.service.host.hostname != str(r.service.host.ip) else '',
                    r.service.name,
                    r.service.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.service.protocol),
                    r.type or '',
                    username,
                    password,
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
        :return: Newly created credential
        :rtype: Credential|None
        """
        cred = self.sqlsess.query(Credential).join(Service)\
                           .filter(Service.id == service_id)\
                           .filter(Credential.username == username)\
                           .filter(Credential.password == password)\
                           .filter(Credential.type == auth_type).first()
        if cred:
            logger.warning('Credential already exists in database')
            return None
        else:

            service = self.sqlsess.query(Service).filter(Service.id == service_id)\
                                  .first()
            if not service:
                logger.error('Service id {id} is invalid'.format(id=service_id))
                return None
            else:

                # Check if username already in database
                cred = self.sqlsess.query(Credential).join(Service)\
                                   .filter(Service.id == service_id)\
                                   .filter(Credential.username == username)\
                                   .filter(Credential.type == auth_type).first()

                if cred:
                    if password is None and cred.password is not None:
                        logger.warning('Credential (username + password) already ' \
                            'exists for this user. Not updated.')
                        return

                    elif password is not None and cred.password is None:
                        logger.info('Username already exists in database, the entry ' \
                            'is updated.')
                        cred.password = password

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
                return cred


    #------------------------------------------------------------------------------------

    def edit_cred(self, username, password, comment, auth_type=None):
        """
        Edit selected credentials.
        :param str username: Username of new credential to add
        :param str password: Password of new credential to add (can be None)
        :param str comment: Comment of new credential of add (can be None)
        :param str auth_type: For HTTP, type of credential (can be None)
        :return: Edited credential
        :rtype: Credential|None
        """
        results = self.get_results()
        if not results:
            logger.error('No matching credential')
            return None
        elif len(results) > 1:
            logger.error('Matching with more than 1 credential')
            return None
        else:
            if username is None:
                logger.error('Username cannot be None')
                return None

            cred = results[0]
            cred.username = username
            cred.password = password
            cred.comment = comment
            cred.auth_type = auth_type if cred.service.name == 'http' else None

            self.sqlsess.commit()
            logger.success('Credential edited')
            return cred


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
        """
        Delete selected credentials
        :return: Status
        :rtype: bool
        """
        results = self.get_results()
        if not results:
            logger.error('No matching credential')
            return False
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


