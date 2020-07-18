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
from lib.utils.StringUtils import StringUtils


class CommandOutputsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(CommandOutput).join(Result).join(Service).join(Host)\
                          .join(Mission)
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def show_search_results(self, string, nb_words=12):
        """
        Display command outputs search results.
        For good readability, only some words surrounding the search string are 
        displayed.

        :param str string: Search string (accepts wildcard "%")
        :param int nb_words: Number of words surrounding the search string to show
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
                # There might have several matches in one command result (one row
                # per match)
                for m in match:
                    data.append([
                        r.result.service.host.ip,
                        r.result.service.port,
                        {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                            r.result.service.protocol),
                        r.result.service.name,
                        r.result.id,
                        r.result.category,
                        r.result.check,
                        StringUtils.wrap(m, 70),
                    ])

        print()
        Output.table(columns, data, hrules=False)
        # for o in results:
        #     Output.title3('[{check}] {cmdline}'.format(
        #         check=o.result.check, cmdline=o.cmdline))
        #     print()
        #     print(o.output)
        #     print()   
