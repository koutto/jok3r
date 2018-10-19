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
        query = sqlsession.query(Result)
        super().__init__(sqlsession, query)


    def show_results(self, service_id):
        service = self.sqlsess.query(Service).filter(Service.id == service_id).first()
        if not service:
            logger.error('Invalid service id')
        else:

            Output.title2('Attacks results:')
            Output.title2('Target: host={ip}{hostname} | port={port}/{proto} | service {service}'.format(
                ip       = service.host.ip,
                hostname = ' ('+service.host.hostname+')' if service.host.hostname else '',
                port     = service.port,
                proto    = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(service.protocol),
                service  = service.name))

            results = self.sqlsess.query(Result).filter(Result.service_id == service_id).all()
            if not results:
                logger.warning('No results to display')
            else:
                data = list()
                columns = [
                    'Check id',
                    'Category',
                    'Check',
                    '# Commands',
                ]
                for r in results:
                    data.append([
                        r.id,
                        r.category,
                        r.check,
                        len(r.command_outputs),
                    ])
                Output.table(columns, data, hrules=False)


    def show_command_outputs(self, result_id):
        result_check = self.sqlsess.query(Result).join(Service).join(Host).filter(Result.id == result_id).first()
        if not result_check:
            logger.error('Invalid check id')
            return

        command_outputs = self.sqlsess.query(CommandOutput).filter(CommandOutput.result_id == result_id).all()

        Output.title2('Results for check {check}:'.format(check=result_check.check))
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


    def add_result(self, service_id, check, category, command_outputs):
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