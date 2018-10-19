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

    def __init__(self, service, categories):
        """
        :param service: Service name
        :param categories: List of categories used to classify the various checks
        """
        self.service    = service
        self.categories = categories
        self.checks     = OrderedDefaultDict(list, {k:[] for k in categories}) # {category: [checks]}


    def add_check(self, check):
        """
        Add a Check
        :param check: Check object
        :return: Boolean indicating status
        """
        self.checks[check.category].append(check)
        return True


    def get_check(self, checkname):
        """
        Get a Check object by name (NOT case-sensitive)
        :param checkname: Name of the check to look for
        :return: Check object
        """
        for cat in self.checks:
            for c in self.checks[cat]:
                if c.name.lower() == checkname.lower():
                    return c
        return None


    def is_existing_check(self, checkname):
        """
        Indicates if a given check name is existing for the current service (NOT case-sensitive)
        :param checkname: Name of the check to look for
        :return: Boolean
        """
        return checkname.lower() in [item.name.lower() for sublist in self.checks.values() for item in sublist]


    def run(self, 
            target, 
            smartmodules_loader, 
            results_requester, 
            filter_categories=None, 
            filter_checks=None, 
            fast_mode=False,
            attack_progress=None):
        """
        Run checks for the service.
        By default, all the categories of checks are runned. Otherwise, only a list of categories
        can be runned.
        :param target: Target object
        :param results_requester: ResultsRequester object
        :param filter_categories: list of categories to run (None for all)
        :param filter_checks: list of checks to run (None for all) 
        """
        categories = self.categories if filter_categories is None else filter_categories

        # Standard mode 
        # Selected/all categories of checks are run
        if filter_checks is None:
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
                    status = ' +--> Current check [{cur}/{total}]: {category} > {checkname}'.format(
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
                    #   - Check is matching context (i.e. at least one of its command is matching context),
                    #   - The tool used for the check is well installed
                    if i > 1: print()
                    if check.is_matching_context(target):
                        Output.title2('[{category}][Check {num:02}/{total:02}] {name} > {description}'.format(
                            category    = category.capitalize(),
                            num         = i,
                            total       = len(self.checks[category]),
                            name        = check.name,
                            description = check.description))

                        if not check.tool.installed:
                            logger.warning('Skipped: the tool "{tool}" used by this check is not installed yet ' \
                                '(according to config)'.format(tool=check.tool.name_display))
                        else:
                            try:
                                check.run(target, smartmodules_loader, results_requester, fast_mode=fast_mode)
                            except KeyboardInterrupt:
                                print()
                                logger.warning('Check {check} skipped !'.format(check=check.name))

                    else:
                        logger.info('[{category}][Check {num:02}/{total:02}] {name} > Skipped because target\'s context is not matching'.format(
                            name     = check.name,
                            category = category.capitalize(),
                            num      = i,
                            total    = len(self.checks[category])))
                        time.sleep(.2)
                    i += 1
                    j += 1

            checks_progress.update()
            time.sleep(.5)

            checks_progress.close()     

        # Special mode
        # User has provided list of checks to run (may be one single check)
        else:
            filter_checks = list(filter(lambda x: self.is_existing_check(x), filter_checks))
            if not filter_checks:
                logger.warning('None of the selected checks is existing for the service {service}'.format(service=target.get_service_name()))
                return

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
                status = ' +--> Current check [{cur}/{total}]: {category} > {checkname}'.format(
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
                Output.title2('[Check {num:02}/{total:02}] {name} > {description}'.format(
                        num         = i,
                        total       = len(filter_checks),
                        name        = check.name,
                        description = check.description))
                try:
                    check.run(target, smartmodules_loader, results_requester, fast_mode=fast_mode)
                except KeyboardInterrupt:
                    print()
                    logger.warning('Check {check} skipped !'.format(check=check.name))
                i += 1     

            checks_progress.update()
            time.sleep(.5)

            checks_progress.close()               


    def show(self):
        """
        Show a summary of checks for the service
        :return: None
        """
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
                data.append([
                    check.name,
                    category,
                    check.description,
                    Output.colored(check.tool.name_display, color='grey_19' if not check.tool.installed else None),
                    #len(check.commands),
                ])
        Output.title1('Checks for service {service}'.format(service=self.service))
        Output.table(columns, data, hrules=False)


    def nb_checks(self):
        """
        Get the total number of checks
        :return: Number of checks
        """
        nb = 0
        for category in self.categories:
            nb += len(self.checks[category])
        return nb
