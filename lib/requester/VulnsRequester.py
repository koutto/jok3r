#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Vulns
###
from six.moves.urllib.parse import urlparse
from sqlalchemy.orm import contains_eager

from lib.requester.Requester import Requester
from lib.utils.NetUtils import NetUtils
from lib.utils.StringUtils import StringUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Vuln import Vuln
from lib.db.Service import Service, Protocol
from lib.output.Output import Output
from lib.output.Logger import logger


class VulnsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Vuln).join(Service).join(Host).join(Mission)
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def show(self, truncation=True):
        """Display selected vulnerabilities"""
        results = self.get_results()

        if not results:
            logger.warning('No vulnerability to display')
        else:
            data = list()
            columns = [
                'IP',
                'Service',
                'Port',
                'Proto',    
                'Vulnerability',
            ]
            for r in results:
                data.append([
                    r.service.host.ip,
                    r.service.name,
                    r.service.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.service.protocol),
                    StringUtils.wrap(r.name, 140) if truncation else r.name,
                ])
            Output.table(columns, data, hrules=False)


    #------------------------------------------------------------------------------------

    def edit_vuln_name(self, new_name):
        """
        Edit vuln name of selected vulnerabilities.
        :param str new_name: New name to set
        :return: Status
        :rtype: bool
        """
        results = self.get_results()
        if not results:
            logger.error('No vulnerability selected')
            return False
        else:
            for r in results:
                r.name = new_name
            self.sqlsess.commit()
            logger.success('Vulnerability edited')
            return True


    def delete(self):
        """
        Delete selected vulnerabilities
        :return: Status
        :rtype: bool
        """
        results = self.get_results()
        if not results:
            logger.error('No matching vulnerability')
            return False
        else:
            for r in results:
                logger.info('Vulnerability deleted: "{vuln}" for service={service} ' \
                    'host={ip} port={port}/{proto}'.format(
                        vuln=StringUtils.shorten(r.name, 50),
                        service=r.service.name,
                        ip=r.service.host.ip,
                        port=r.service.port,
                        proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
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
            #'hostname' : Host.hostname,
            'service'  : Service.name,
            'port'     : Service.port,
            'proto'    : Service.protocol,
            'vuln'     : Vuln.name,
        }

        if column.lower() not in mapping.keys():
            logger.warning('Ordering by column {col} is not supported'.format(
                col=column.lower()))
            return

        super().order_by(mapping[column.lower()])
