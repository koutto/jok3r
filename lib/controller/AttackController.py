#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Attack Controller
###
import datetime
from humanfriendly import format_timespan

from lib.core.AttackScope import AttackScope
from lib.core.Constants import *
from lib.core.Exceptions import AttackException, TargetException
from lib.core.Target import Target
from lib.controller.Controller import Controller
from lib.requester.ServicesRequester import ServicesRequester
from lib.db.Credential import Credential
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Option import Option
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger


class AttackController(Controller):

    def run(self):
        """Run the Attack Controller"""

        args = self.arguments.args
        logger.debug('CLI arguments:')
        logger.debug(args)

        # Attack configuration: Categories of checks to run
        categories = self.settings.services.list_all_categories() # default: all

        if args.cat_only:
            categories = [ cat for cat in categories if cat in args.cat_only ]
        elif args.cat_exclude:
            categories = [ cat for cat in categories if cat not in args.cat_exclude ]


        # Create the attack scope
        self.attack_scope = AttackScope(
            self.settings, 
            self.arguments,
            self.sqlsess,
            args.mission or args.add,
            filter_categories=categories, 
            filter_checks=args.checks, 
            attack_profile=args.profile,
            fast_mode=args.fast_mode)


        # Run the attack
        begin = datetime.datetime.now()
        if args.target_ip_or_url:
            self.__run_for_single_target(args)
        else:
            self.__run_for_multi_targets(args)
            
        print()
        duration = datetime.datetime.now() - begin
        logger.info('Finished. Duration: {}'.format(format_timespan(duration.seconds)))


    #------------------------------------------------------------------------------------
    # Single-Target mode

    def __run_for_single_target(self, args):
        """Run attack against a single target specified into args"""
        
        req = ServicesRequester(self.sqlsess)
        mission = None

        # Get Mission if target must be added into a mission scope
        if args.add:
            mission = self.sqlsess.query(Mission).filter(Mission.name == args.add).first()
            if not mission:
                raise AttackException('The specified mission does not exist in the ' \
                    'database. You should create it if needed')

        # Create new Service/Host objects (if service already exist, 
        # will be merged by ServicesRequester.add_target)
        url = args.target_ip_or_url if args.target_mode == TargetMode.URL else ''
        ip  = args.target_ip_or_url if args.target_mode == TargetMode.IP else ''
        service = Service(
            name=args.service,
            port=int(args.target_port),
            protocol=self.settings.services.get_protocol2(args.service),
            url=url)
        host = Host(ip=ip) # Will be updated when initializing Target()
        host.services.append(service)

        # Update context (credentials, options, products) if specified in command-line
        if args.creds:
            for c in args.creds[args.service]:
                self.sqlsess.add(c)
                service.credentials.append(c)
        if args.users:
            for u in args.users[args.service]: 
                self.sqlsess.add(u)
                service.credentials.append(u)
        if args.products:
            for p in args.products[args.service]: 
                self.sqlsess.add(p)
                service.products.append(p)
        if args.options:
            for o in args.options[args.service]: 
                self.sqlsess.add(o)
                service.options.append(o)

        # Initialize Target
        try:
            target = Target(service, self.settings.services)
        except TargetException as e:
            logger.error(e)
            sys.exit(1)

        # Check Target and update its information:
        # - Reverse DNS lookup: by default
        # - Port check: always
        # - Nmap service detection: by default
        # - HTML title grabbing: always
        # - Web technologies detection: always
        # - Context initialization via SmartStart: always
        reachable = target.smart_check(
            reverse_dns_lookup=(args.reverse_dns is None or args.reverse_dns == 'on'),
            availability_check=True, 
            nmap_banner_grabbing=(args.nmap_banner_grab is None \
                or args.nmap_banner_grab == 'on'),
            html_title_grabbing=True,
            web_technos_detection=True,
            smart_context_initialize=True)

        # Display availability status, exit if not reachable
        if args.target_mode == TargetMode.IP:
            msg = 'Target service {neg}reachable: {target}'.format(
                neg='not ' if not reachable else '',
                target=target)
        else:
            msg = 'Target URL {url} is {neg}reachable'.format(
                url=target.get_url(),
                neg='not ' if not reachable else '')

        if reachable:
            logger.success(msg)
        else: 
            logger.error(msg)
            return

        # Commit the target with updated information inside the appropriate 
        # mission in the database
        if mission:
            logger.info('Results from this attack will be saved under mission ' \
                '"{mission}" in database'.format(mission=mission.name))
            req.select_mission(mission.name)
            req.add_target(target)

        # Run the attack
        self.attack_scope.add_target(target)
        self.attack_scope.attack()
        return


    #------------------------------------------------------------------------------------
    # Multi-Targets mode

    def __run_for_multi_targets(self, args):
        """Run attack against multiple targets from the database"""

        # Get Mission from which targets must be extracted
        mission = self.sqlsess.query(Mission)\
                    .filter(Mission.name == args.mission).first()
        if mission:
            logger.info('Extracting targets from mission "{mission}" ...'.format(
                mission=mission.name))
        else:
            raise AttackException('Mission {mission} does not exist into the ' \
                'database'.format(mission=args.mission))

        # Initialize Services requester and add filter if provided
        req = ServicesRequester(self.sqlsess)
        req.select_mission(args.mission)

        if args.filters_combined:
            for filt in args.filter:
                logger.info('Applying filters on mission scope: {filter}'.format(
                    filter=filt))
            if len(args.filter) > 1:
                logger.info('Note: Logical OR is applied between each filter')
            req.add_filter(args.filters_combined)

        # Retrieve targeted services from database
        services = req.get_results()
        if not services:
            raise AttackException('There is no matching service to target into the ' \
                'database')

        # Add each targeted service into Attack scope 
        for service in services:

            # Update credentials, options, products if specified in command-line
            if args.creds:
                for c in args.creds[service.name]: 
                    service.add_credential(c.clone())
            if args.users:
                for u in args.users[service.name]: 
                    service.add_credential(u.clone())
            if args.products:
                for p in args.products[service.name]: 
                    service.add_product(p.clone())
            if args.options:
                for o in args.options[service.name]: 
                    service.add_option(o.clone())

            # Initialize Target 
            try:
                target = Target(service, self.settings.services)
            except TargetException as e:
                logger.error(e)
                continue

            self.attack_scope.add_target(target)

        # Run the attack
        self.attack_scope.attack()