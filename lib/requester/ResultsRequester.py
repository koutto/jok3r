#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Results
###
from lib.requester.Requester import Requester
from lib.db.CommandOutput import CommandOutput
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Result import Result
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger
from lib.output.Output import Output


class ResultsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Result).join(Service).join(Host).join(Mission)
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def show(self):
        """Display selected results"""
        results = self.get_results()

        Output.title2('Attacks results:')

        if not results:
            logger.warning('No results to display')
        else:
            data = list()
            columns = [
                'IP',
                'Port',
                'Proto',
                'Service',
                'Check id',
                'Category',
                'Check',
                '# Commands run',
            ]
            for r in results:
                data.append([
                    r.service.host.ip,
                    r.service.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.service.protocol),
                    r.service.name,
                    r.id,
                    r.category,
                    r.check,
                    len(r.command_outputs),
                ])
            Output.table(columns, data, hrules=False)


    def show_command_outputs_for_check(self):
        """
        Display command outputs text for selected result/check
        This method must call only when filtering on one Result.id, i.e. 
        Condition(xxx, FilterData.CHECK_ID)
        """
        result = self.get_first_result()

        if not result:
            logger.error('Invalid check id (not existing)')
        else:
            Output.title2('Results for check {category} > {check}:'.format(
                category = result.category, 
                check    = result.check))

            if result.service.host.hostname:
                hostname = ' ('+result.service.host.hostname+')'
            else:
                hostname = ''

            Output.title2('Target: host={ip}{hostname} | port={port}/{proto} | ' \
                'service {service}'.format(
                ip       = result.service.host.ip,
                hostname = hostname,
                port     = result.service.port,
                proto    = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                    result.service.protocol),
                service  = result.service.name))

            print()
            for o in command_outputs:
                Output.title3(o.cmdline)
                print()
                print(o.output)
                print()   


    #------------------------------------------------------------------------------------

    def add_result(self, service_id, check, category, command_outputs):
        """
        Add new result for given service.
        :param int service_id: Id of service
        :param str check: Name of the check to add
        :param str category: Category of the check
        :param str command_output: Command output text
        """
        matching_check = self.sqlsess.query(Result).filter_by(service_id = service_id)\
                                     .filter(Result.check == check).first()
        if matching_check:
            for output in command_outputs:
                matching_check.command_outputs.append(output)
        else:
            result = Result(category=category, check=check, service_id=service_id)
            result.command_outputs = command_outputs
            self.sqlsess.add(result)

        self.sqlsess.commit()