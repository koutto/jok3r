#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Options
###
from lib.requester.Requester import Requester
from lib.utils.StringUtils import StringUtils
from lib.db.Credential import Credential
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Option import Option
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger
from lib.output.Output import Output


class OptionsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Option).join(Service).join(Host).join(Mission)
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def show(self):
        """Display selected specific options"""
        results = self.get_results()

        if not results:
            logger.warning('No specific option to display')
        else:
            data = list()
            columns = [
                'IP',
                'Hostname',
                'Service',
                'Port',
                'Proto',
                'Name',
                'Value',
            ]
            for r in results:
                data.append([
                    r.service.host.ip,
                    r.service.host.hostname \
                        if r.service.host.hostname != str(r.service.host.ip) else '',
                    r.service.name,
                    r.service.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.service.protocol),
                    r.name,
                    r.value,
                ])
            Output.table(columns, data, hrules=False)


    #------------------------------------------------------------------------------------

    def delete(self):
        """Delete selected specific options"""
        results = self.get_results()
        if not results:
            logger.error('No matching specific option')
        else:
            for r in results:
                logger.info('Option {name}={value} for host={ip} service={service} ' \
                    '({port}/{proto}) deleted'.format(
                        name=r.name,
                        value=r.value,
                        ip=r.service.host.ip,
                        service=r.service.name,
                        port=r.service.port,
                        proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
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
            'service'  : Service.name,
            'port'     : Service.port,
            'proto'    : Service.protocol,
            'name'     : Option.name,
            'value'    : Option.value,
        }

        if column.lower() not in mapping.keys():
            logger.warning('Ordering by column {col} is not supported'.format(
                col=column.lower()))
            return

        super().order_by(mapping[column.lower()])

