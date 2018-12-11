#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Command Outputs
###
from lib.requester.Requester import Requester
from lib.db.CommandOutput import CommandOutput
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Result import Result
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger
from lib.output.Output import Output


class CommandOutputsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(CommandOutput).query(Result).join(Service).join(Host)\
                          .join(Mission)
        super().__init__(sqlsession, query)


    def show_search_results(self, string, nb_words=12):
        """

        """
        results = self.query.filter(CommandOutput.output.ilike('%'+string+'%'))
        if not results:
            logger.error('No result')
        else:
            Output.title2('Search results:')

            data = list()
            columns = [
                'IP',
                'Port',
                'Proto',
                'Service',
                'Check id',
                'Category',
                'Check',
                'Matching text',
            ]
            for r in results:
                match = StringUtils.surrounding_text(r.outputraw, string, nb_words)
                data.append([
                    r.result.service.host.ip,
                    r.result.service.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        r.result.service.protocol),
                    r.result.service.name,
                    r.result.id,
                    r.result.category,
                    r.result.check,
                    match,
                ])

        print()
        for o in command_outputs:
            Output.title3(o.cmdline)
            print()
            print(o.output)
            print()   
