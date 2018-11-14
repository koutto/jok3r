#!/usr/bin/env python3
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
    """Stores all targets selected for the current attack."""

    def __init__(self, 
                 settings, 
                 results_requester,
                 smartmodules_loader,
                 filter_categories=None, 
                 filter_checks=None, 
                 fast_mode=False):
        """
        Construct AttackScope object

        :param Settings settings: Settings
        :param ResultsRequester results_requester: Accessor for Result model
        :param SmartModulesLoader smartmodules_loader: Loader of Smart modules
        :param list filter_categories: Selection of categories of checks to run 
            (default is None, for all categories)
        :param list filter_checks: Selection of checks to run
            (default is None, for all checks)
        :param bool fast_mode: Set to true to disable prompts
        """
        self.settings            = settings
        self.results_requester   = results_requester
        self.smartmodules_loader = smartmodules_loader
        self.targets             = list()
        self.current_targetid    = 1
        self.filter_categories   = filter_categories
        self.filter_checks       = filter_checks
        self.fast_mode           = fast_mode


    #------------------------------------------------------------------------------------

    def add_target(self, target):
        """
        Add a target to the scope.

        :param Target target: Target to add
        """ 
        self.targets.append(target)


    #------------------------------------------------------------------------------------
    # Run Methods

    def attack(self):
        """Run the attack against all targets in the scope"""

        # Initialize top status/progress bar
        # If single target (total=None), the counter format will be used instead of 
        # the progress bar format
        attack_progress = manager.counter(
            total=len(self.targets)+1 if len(self.targets) > 1 else None, 
            desc='', 
            unit='target',
            bar_format=STATUSBAR_FORMAT, # For multi targets
            counter_format=STATUSBAR_FORMAT_SINGLE) # For single target

        time.sleep(.5) # hack for progress bar display

        # Loop over the targets
        for i in range(1,len(self.targets)+1):

            print()
            self.show_summary()
            print()

            # Prompt for target selection
            if not self.fast_mode:
                if len(self.targets) > 1:
                    self.current_targetid = Output.prompt_choice_range(
                        'Attack target # ? [{default}] '.format(
                            default=self.current_targetid), 
                        1, len(self.targets), self.current_targetid)
                else:
                    if Output.prompt_confirm('Start attack ?', default=True):
                        self.current_targetid = 1
                    else:
                        logger.warning('Attack canceled !')
                        sys.exit(1)

            target = self.targets[self.current_targetid-1]

            # Update status/progress bar
            status = 'Current target [{cur}/{total}]: {target}'.format(
                    cur    = i,
                    total  = len(self.targets),
                    target = target)

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
        Run security checks against one target.

        :param int id_: Identifier of the target to attack (as displayed in "id" 
            column in show_summary())
        :param enlighten.Counter attack_progress: Attack progress
        """
        target = self.targets[id_-1]

        # Print target information
        target.print_http_headers()
        target.print_context()

        # Run start method from SmartModule
        self.smartmodules_loader.call_start_method(target.service)

        # Run security cehecks
        service_checks = self.settings.services.get_service_checks(
            target.get_service_name())
        service_checks.run(target, 
                           self.smartmodules_loader,
                           self.results_requester, 
                           self.filter_categories, 
                           self.filter_checks,
                           fast_mode=self.fast_mode, 
                           attack_progress=attack_progress)


    #------------------------------------------------------------------------------------
    # Output methods

    def show_summary(self):
        """
        """
        data = list()
        columns = [
            'id',
            'IP/',
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
                Output.colored('>'+str(id_) if self.current_targetid == id_ \
                               else str(id_), 
                    color=pointer_color, attrs=pointer_attr),
                Output.colored(target.get_ip(), 
                    color=pointer_color, attrs=pointer_attr),
                Output.colored(StringUtils.wrap(target.get_host(), 50), 
                    color=pointer_color, attrs=pointer_attr),
                Output.colored(str(target.get_port()), 
                    color=pointer_color, attrs=pointer_attr),
                Output.colored(target.get_protocol(), 
                    color=pointer_color, attrs=pointer_attr),
                Output.colored(target.get_service_name(), 
                    color=pointer_color, attrs=pointer_attr),
                Output.colored(StringUtils.wrap(target.get_banner(), 55), 
                    color=pointer_color, attrs=pointer_attr),
                Output.colored(StringUtils.wrap(target.get_url(), 50), 
                    color=pointer_color, attrs=pointer_attr),
            ])
            id_ += 1
        Output.table(columns, data, hrules=False)

