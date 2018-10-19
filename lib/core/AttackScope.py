# -*- coding: utf-8 -*-
###
### Core > AttackScope
###
import sys
import time

from lib.utils.StringUtils import StringUtils
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.output.StatusBar import *


class AttackScope:

    def __init__(self, 
                 settings, 
                 results_requester,
                 smartmodules_loader,
                 filter_categories=None, 
                 filter_checks=None, 
                 fast_mode=False):
        """
        :param settings: Settings object
        :param results_requester: ResultsRequester object
        :param filter_categories: List of categories of checks to run (None for all)
        :param filter_checks: List of checks to run (None for all)
        """
        self.settings            = settings
        self.results_requester   = results_requester
        self.smartmodules_loader = smartmodules_loader
        self.targets             = list()
        self.current_targetid    = 1
        self.filter_categories   = filter_categories
        self.filter_checks       = filter_checks
        self.fast_mode           = fast_mode


    def add_target(self, target):
        """
        :param target: Target object
        """ 
        self.targets.append(target)


    def attack(self):
        """
        Run the attack against all targets
        :param fast_mode:
        """

        # Initialize top status/progress bar
        # If single target (total=None), the counter format will be used instead of the progress bar format
        attack_progress = manager.counter(total=len(self.targets)+1 if len(self.targets) > 1 else None, 
                                          desc='', 
                                          unit='target',
                                          bar_format=STATUSBAR_FORMAT, # For multi targets
                                          counter_format=STATUSBAR_FORMAT_SINGLE) # For single target

        time.sleep(.5) # hack for progress bar display

        for i in range(1,len(self.targets)+1):
            print()
            self.show_summary()
            print()

            # Target selection
            if not self.fast_mode:
                if len(self.targets) > 1:
                    self.current_targetid = Output.prompt_choice_range('Attack target # ? [{default}] '.format(
                        default=self.current_targetid), 1, len(self.targets), self.current_targetid)
                else:
                    if Output.prompt_confirm('Start attack ?', default=True):
                        self.current_targetid = 1
                    else:
                        logger.warning('Attack canceled !')
                        sys.exit(1)

            target = self.targets[self.current_targetid-1]

            # Update status/progress bar
            status = 'Current target [{cur}/{total}]: host {ip} | port {port}/{proto} | service {service}'.format(
                cur    = i,
                total  = len(self.targets),
                ip      = target.get_ip(),
                port    = target.get_port(),
                proto   = target.get_protocol(),
                service = target.get_service_name())
            attack_progress.desc = '{status}{fill}'.format(
                status = status,
                fill   = ' '*(DESC_LENGTH-len(status)))
            attack_progress.update()
            print()

            # Launch the attack on the selected target
            self.__attack_target(self.current_targetid, attack_progress)
            self.current_targetid += 1

        attack_progress.update()
        time.sleep(.5)

        attack_progress.close()
        manager.stop() # Clear progress bars


    def __attack_target(self, id_, attack_progress):
        """
        Run checks against a given target
        :param id_: Number of the target (as displayed in "id" column in show_summary())
        """
        target = self.targets[id_-1]

        if target.get_http_headers():
            logger.info('HTTP Response headers:')
            for l in target.get_http_headers().splitlines():
                Output.print(l)
            print()

        if target.get_credentials():
            logger.info('Credentials set for this target:')
            data = list()
            columns = ['username', 'password']
            if target.get_service_name() == 'http': columns.append('auth-type')
            for c in target.get_credentials():
                username = '<empty>' if c.username == '' else c.username
                if c.password is None:
                    password = '???'
                else:
                    password = '<empty>' if c.password == '' else c.password

                line = [username, password]
                if target.get_service_name() == 'http': line.append(c.type)
                data.append(line)
            Output.table(columns, data, hrules=False)

        if target.get_specific_options():
            logger.info('Context-specific options set for this target:')
            data = list()
            columns = ['option', 'value']
            for o in target.get_specific_options():
                data.append([o.name, o.value])
            Output.table(columns, data, hrules=False)

        # TODO: add/edit specific options before run
        self.smartmodules_loader.call_start_method(target.service)

        service_checks = self.settings.services.get_service_checks(target.get_service_name())
        service_checks.run(target, 
                           self.smartmodules_loader,
                           self.results_requester, 
                           self.filter_categories, 
                           self.filter_checks,
                           fast_mode=self.fast_mode, 
                           attack_progress=attack_progress)


    def show_summary(self):
        """
        """
        data = list()
        columns = [
            'id',
            'IP',
            'Hostname',
            'Port',
            'Proto',
            'Service',
            'Banner',
            'URL',
        ]
        id_ = 1
        for target in self.targets:
            pointer_color = 'blue'   if self.current_targetid == id_ else None
            pointer_attr  = 'bold' if self.current_targetid == id_ else None
            data.append([
                Output.colored('>'+str(id_) if self.current_targetid == id_ else str(id_), color=pointer_color, attrs=pointer_attr),
                Output.colored(target.get_ip(), color=pointer_color, attrs=pointer_attr),
                Output.colored(target.get_host(), color=pointer_color, attrs=pointer_attr),
                Output.colored(str(target.get_port()), color=pointer_color, attrs=pointer_attr),
                Output.colored(target.get_protocol(), color=pointer_color, attrs=pointer_attr),
                Output.colored(target.get_service_name(), color=pointer_color, attrs=pointer_attr),
                Output.colored(StringUtils.wrap(target.get_banner(), 70), color=pointer_color, attrs=pointer_attr),
                Output.colored(StringUtils.wrap(target.get_url(), 50), color=pointer_color, attrs=pointer_attr),
            ])
            id_ += 1
        Output.table(columns, data, hrules=False)

