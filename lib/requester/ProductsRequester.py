#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Products
###
from six.moves.urllib.parse import urlparse
from sqlalchemy.orm import contains_eager

from lib.requester.Requester import Requester
from lib.utils.NetUtils import NetUtils
from lib.utils.StringUtils import StringUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Product import Product
from lib.db.Service import Service, Protocol
from lib.output.Output import Output
from lib.output.Logger import logger


class ProductsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Product).join(Service).join(Host).join(Mission)
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def show(self):
        """Show selected products"""
        results = self.get_results()

        if not results:
            logger.warning('No product to display')
        else:
            data = list()
            columns = [
                'IP',
                'Hostname',
                'Service',
                'Port',
                'Proto',
                'Type',
                'Name',
                'Version',
            ]
            for r in results:
                data.append([
                    r.service.host.ip,
                    r.service.host.hostname,
                    r.service.name,
                    r.service.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.service.protocol),
                    r.type,
                    r.name,
                    r.version,
                ])
            Output.table(columns, data, hrules=False)


    #------------------------------------------------------------------------------------

    def delete(self):
        """Delete selected products"""
        results = self.get_results()
        if not results:
            logger.error('No matching product')
        else:
            for r in results:
                logger.info('Product deleted: {type}={name}{version} for ' \
                    'service={service} host={ip} port={port}/{proto}'.format(
                        type    = r.type,
                        name    = r.name,
                        version = ' '+r.version if r.version else '',
                        service = r.service.name,
                        ip      = r.service.host.ip,
                        port    = r.service.port,
                        proto   = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
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
            'type'     : Product.type,
            'name'     : Product.name,
            'version'  : Product.version,
        }

        if column.lower() not in mapping.keys():
            logger.warning('Ordering by column {col} is not supported'.format(
                col=column.lower()))
            return

        super().order_by(mapping[column.lower()])
