#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Service Checks
###
import time

from lib.utils.OrderedDefaultDict import OrderedDefaultDict
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.output.StatusBar import *

class ServiceChecks:
    """All Security Checks for a Service"""

    def __init__(self, service, categories):
        """
        Construct ServiceChecks object.

        :param str service: Service name
        :param list categories: Categories used to classify the various checks
        """
        self.service = service
        self.categories = categories
        # Organize checks in dict {category: [checks]}
        self.checks = OrderedDefaultDict(list, {k:[] for k in categories})


    #------------------------------------------------------------------------------------
    # Basic Operations

    def add_check(self, check):
        """
        Add a Check.

        :param Check check: The check to add
        :return: Status
        :rtype: bool
        """
        self.checks[check.category].append(check)
        return True


    def get_check(self, checkname):
        """
        Get a check by name (NOT case-sensitive).

        :param checkname: Name of the check to get
        :return: Check if found, None otherwise
        :rtype: Check|None
        """
        for cat in self.checks:
            for c in self.checks[cat]:
                if c.name.lower() == checkname.lower():
                    return c
        return None


    def get_all_check_names(self):
        """
        Get list of names of all checks.

        :return: Names of all checks
        :rtype: list
        """
        return [item.name for sublist in self.checks.values() for item in sublist]


    def is_existing_check(self, checkname):
        """
        Indicates if a given check name is existing for the current service 
        (NOT case-sensitive)

        :param checkname: Name of the check to look for
        :return: Result of the search
        :rtype: bool
        """
        return checkname.lower() in map(lambda x: x.lower(), self.get_all_check_names())


    def nb_checks(self):
        """
        Get the total number of checks

        :return: Number of checks
        :rtype: int
        """
        nb = 0
        for category in self.categories:
            nb += len(self.checks[category])
        return nb


    #------------------------------------------------------------------------------------
    # Run 

    def run(self, 
            target, 
            arguments,
            sqlsession,
            results_requester, 
            filter_categories=None, 
            filter_checks=None, 
            attack_profile=None,
            fast_mode=False,
            attack_progress=None):
        """
        Run checks for the service.
        By default, all the checks are runned (but commands are actually run only if 
        target complies with context requirements). It is however possible to apply 
        filters to select the checks to run:
            - Filter on categories,
            - Filter on names of checks.

        :param Target target: Target
        :param ArgumentsParser arguments: Arguments from command-line
        :param Session sqlsession: SQLAlchemy session
        :param ResultsRequester results_requester: Accessor for Results Model
        :param list filter_categories: Selection of categories to run (default: all)
        :param list filter_checks: Selection of checks to run (default: all)
        :param AttackProfile attack_profile: Attack profile (default: no profile)
        :param bool fast_mode: Set to true to disable prompts
        :param enlighten.Counter attack_progress: Attack progress
        """
        categories = self.categories if filter_categories is None else filter_categories

        # Standard mode 
        # Selected/all categories of checks are run
        if filter_checks is None and attack_profile is None:
            nb_checks = self.nb_checks()

            # Initialize sub status/progress bar
            checks_progress = manager.counter(total=nb_checks+1, 
                                              desc='', 
                                              unit='check',
                                              leave=False,
                                              bar_format=STATUSBAR_FORMAT)
            time.sleep(.5) # hack for progress bar display

            j = 1
            for category in categories:

                Output.title1('Category > {cat}'.format(cat=category.capitalize()))

                i = 1
                for check in self.checks[category]:

                    # Update status/progress bar
                    status = ' +--> Current check [{cur}/{total}]: {category} > ' \
                        '{checkname}'.format(
                            cur       = j,
                            total     = nb_checks,
                            category  = check.category,
                            checkname = check.name)

                    checks_progress.desc = '{status}{fill}'.format(
                        status = status,
                        fill   = ' '*(DESC_LENGTH-len(status)))
                    checks_progress.update()
                    if attack_progress:
                        # Hack to refresh the attack progress bar without incrementing
                        # useful if the tool run during the check has cleared the screen
                        attack_progress.refresh()


                    # Run the check if and only if:
                    #   - Target is compliant with the check,
                    #   - The tool used for the check is well installed.
                    if i > 1: print()
                    if check.check_target_compliance(target):
                        Output.title2('[{category}][Check {num:02}/{total:02}] ' \
                            '{name} > {description}'.format(
                                category    = category.capitalize(),
                                num         = j,
                                total       = nb_checks,
                                name        = check.name,
                                description = check.description))

                        if not check.tool.installed:
                            logger.warning('Skipped: the tool "{tool}" used by this ' \
                                'check is not installed yet'.format(
                                    tool=check.tool.name))
                        else:
                            try:
                                check.run(target, 
                                          arguments,
                                          sqlsession,
                                          results_requester, 
                                          fast_mode=fast_mode)

                            except KeyboardInterrupt:
                                print()
                                logger.warning('Check {check} skipped !'.format(
                                    check=check.name))

                    else:
                        logger.info('[{category}][Check {num:02}/{total:02}] {name} > ' \
                            'Skipped because context requirements does not apply to ' \
                            'the target'.format(
                                name     = check.name,
                                category = category.capitalize(),
                                num      = j,
                                total    = nb_checks))
                        time.sleep(.2)
                    i += 1
                    j += 1

            checks_progress.update()
            time.sleep(.5)

            checks_progress.close()     

        # Special mode
        # User has provided either an attack profile or a list of checks to run 
        # (may be one single check)
        else:

            # User has submitted list of checks
            if filter_checks:
                filter_checks = list(filter(
                    lambda x: self.is_existing_check(x), filter_checks))

                if not filter_checks:
                    logger.warning('None of the selected checks is existing for the ' \
                        'service {service}'.format(service=target.get_service_name()))
                    return

            # User has submitted an attack profile
            else:
                if not attack_profile.is_service_supported(target.get_service_name()):
                    logger.warning('The attack profile {profile} is not supported for ' \
                        'target service {service}'.format(
                            profile=attack_profile, service=target.get_service_name()))
                    return
                else:
                    filter_checks = attack_profile.get_checks_for_service(
                        target.get_service_name())
 

            # Initialize sub status/progress bar
            checks_progress = manager.counter(total=len(filter_checks)+1, 
                                              desc='', 
                                              unit='check',
                                              leave=False,
                                              bar_format=STATUSBAR_FORMAT)
            time.sleep(.5) # hack for progress bar display

            i = 1
            for checkname in filter_checks:
                print()
                check = self.get_check(checkname)

                # Update status/progress bar
                status = ' +--> Current check [{cur}/{total}]: {category} > ' \
                    '{checkname}'.format(
                        cur       = i,
                        total     = len(filter_checks),
                        category  = check.category,
                        checkname = checkname)

                checks_progress.desc = '{status}{fill}'.format(
                    status = status,
                    fill   = ' '*(DESC_LENGTH-len(status)))
                checks_progress.update()
                if attack_progress:
                    # Hack to refresh the attack progress bar without incrementing
                    # useful if the tool run during the check has cleared the screen
                    attack_progress.update(incr=0, force=True) 

                # Run the check
                Output.title2('[Check {num:02}/{total:02}] {name} > ' \
                    '{description}'.format(
                        num         = i,
                        total       = len(filter_checks),
                        name        = check.name,
                        description = check.description))
                try:
                    check.run(target, 
                              arguments,
                              sqlsession,
                              results_requester, 
                              fast_mode=fast_mode)
                except KeyboardInterrupt:
                    print()
                    logger.warning('Check {check} skipped !'.format(check=check.name))

                i += 1     

            checks_progress.update()
            time.sleep(.5)

            checks_progress.close()               


    #------------------------------------------------------------------------------------
    # Output methods

    def show(self):
        """Display a table with all the checks for the service."""
        data = list()
        columns = [
            'Name',
            'Category',
            'Description',
            'Tool used',
            #'# Commands',
        ]
        for category in self.categories:
            for check in self.checks[category]:
                color_tool = 'grey_19' if not check.tool.installed else None
                data.append([
                    check.name,
                    category,
                    check.description,
                    Output.colored(check.tool.name, color=color_tool),
                    #len(check.commands),
                ])
                
        Output.title1('Checks for service {service}'.format(service=self.service))
        Output.table(columns, data, hrules=False)



