#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > AttackScope
###
import sys
import time

from lib.requester.ResultsRequester import ResultsRequester
from lib.requester.ServicesRequester import ServicesRequester
from lib.smartmodules.SmartStart import SmartStart
from lib.utils.StringUtils import StringUtils
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.output.StatusBar import *


class AttackScope:
    """Stores all targets selected for the current attack."""

    def __init__(self, 
                 settings, 
                 arguments,
                 sqlsession,
                 mission,
                 filter_categories=None, 
                 filter_checks=None, 
                 attack_profile=None,
                 fast_mode=False):
        """
        Construct AttackScope object

        :param Settings settings: Settings
        :param ArgumentsParser arguments: Arguments from command-line
        :param Session sqlsession: SQLAlchemy session
        :param str mission: Mission name
        :param list filter_categories: Selection of categories of checks to run 
            (default is None, for all categories)
        :param list filter_checks: Selection of checks to run
            (default is None, for all checks)
        :param AttackProfile attack_profile: Attack profile
            (default is None, meaning no profile)
        :param bool fast_mode: Set to true to disable prompts
        """
        self.settings            = settings
        self.arguments           = arguments
        self.sqlsess             = sqlsession
        self.mission_name        = mission
        self.services_requester  = ServicesRequester(self.sqlsess)
        self.targets             = list()
        self.current_targetid    = 1
        self.filter_categories   = filter_categories
        self.filter_checks       = filter_checks
        self.attack_profile      = attack_profile
        self.fast_mode           = fast_mode

        self.services_requester.select_mission(self.mission_name)


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

            # In Multi-targets mode: 
            # Display summary table and prompt for target selection 
            # (not if too many target to avoid poor output)
            if 2 <= len(self.targets) <= 15:
                self.show_summary()

            if not self.fast_mode and len(self.targets) > 1:
                self.current_targetid = Output.prompt_choice_range(
                    'Attack target # (Ctrl+C to quit) ? [{default}] '.format(
                        default=self.current_targetid), 
                    1, len(self.targets), self.current_targetid)

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

            # Check the current target
            # For single target mode: already done in AttackController
            if len(self.targets) > 1:
                # By default, do NOT perform reverve DNS lookup & Nmap banner grabbing
                # because we assume it has been added via Nmap results in most cases
                # and thus, has already been done (behaviour can be changed with opt)
                reachable = target.smart_check(
                    reverse_dns=(self.arguments.args.reverse_dns == 'on'),
                    availability_check=True,
                    grab_banner_nmap=(self.arguments.args.nmap_banner_grab == 'on'),
                    web_technos_detection=False)

                if target.service.name == 'http':
                    msg = 'Target URL {url} is {neg}reachable'.format(
                        url=target.get_url(),
                        neg='not ' if not reachable else '')
                else:
                    msg = 'Target {neg}reachable: {target}'.format(
                        neg='not ' if not reachable else '',
                        target=target)

                # Update info into database if needed
                self.services_requester.add_target(target)

                if reachable:
                    #target.service.up = True
                    logger.success(msg)
                else: 
                    # Skip target if not reachable
                    logger.error(msg)
                    continue


            # In Single-target mode: Display summary table and prompt for confirmation
            if len(self.targets) == 1:
                self.show_summary()

                if not self.fast_mode:
                    if Output.prompt_confirm('Start attack ?', default=True):
                        self.current_targetid = 1
                    else:
                        logger.warning('Attack canceled !')
                        sys.exit(1)

            # Launch the attack on the selected target
            self.__attack_target(target, attack_progress)
            self.current_targetid += 1
            self.current_targetid = self.current_targetid % len(self.targets)

        attack_progress.update()
        time.sleep(.5)

        attack_progress.close()
        manager.stop() # Clear progress bars


    def __attack_target(self, target, attack_progress):
        """
        Run security checks against one target.

        :param Target target: The Target
        :param enlighten.Counter attack_progress: Attack progress
        """
                   
        # Print target information
        target.print_http_headers()
        target.print_context()

        # Run start method from SmartModule
        start = SmartStart(target.service, self.sqlsess)
        start.run()

        # Run security checks
        service_checks = self.settings.services.get_service_checks(
            target.get_service_name())
        service_checks.run(target, 
                           self.arguments,
                           self.sqlsess,
                           filter_categories=self.filter_categories, 
                           filter_checks=self.filter_checks,
                           attack_profile=self.attack_profile,
                           fast_mode=self.fast_mode, 
                           attack_progress=attack_progress)


    #------------------------------------------------------------------------------------
    # Output methods

    def show_summary(self):
        """Display a table showing the summary of the attack scope."""
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

        print()
        Output.table(columns, data, hrules=False)
        print()

