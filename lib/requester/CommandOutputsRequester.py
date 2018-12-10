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
        query = sqlsession.query(CommandOutput).query(Result).join(Service).join(Host)
        super().__init__(sqlsession, query)


    def show_command_outputs(self, result_id):
        result_check = self.sqlsess.query(Result).join(Service).join(Host)\
                                   .filter(Result.id == result_id).first()
        if not result_check:
            logger.error('Invalid check id')
            return

        command_outputs = self.sqlsess.query(CommandOutput)\
                                      .filter(CommandOutput.result_id == result_id).all()

        Output.title2('Results for check {category} > {check}:'.format(
            category = result_check.category, 
            check    = result_check.check))
        Output.title2('Target: host={ip}{hostname} | port={port}/{proto} | service {service}'.format(
            ip       = result_check.service.host.ip,
            hostname = ' ('+result_check.service.host.hostname+')' if result_check.service.host.hostname else '',
            port     = result_check.service.port,
            proto    = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(result_check.service.protocol),
            service  = result_check.service.name))

        print()
        for o in command_outputs:
            Output.title3(o.cmdline)
            print()
            print(o.output)
            print()   
