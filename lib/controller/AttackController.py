#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Attack Controller
###
import time
from collections import defaultdict

from lib.core.AttackScope import AttackScope
from lib.core.Constants import *
from lib.core.Exceptions import AttackException
from lib.core.Target import Target
from lib.controller.Controller import Controller
from lib.requester.ResultsRequester import ResultsRequester
from lib.requester.ServicesRequester import ServicesRequester
from lib.db.Credential import Credential
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Option import Option
from lib.db.Service import Service, Protocol
from lib.smartmodules.SmartModulesLoader import SmartModulesLoader
from lib.output.Logger import logger


class AttackController(Controller):

    def run(self):
        """Run the Attack Controller"""

        args = self.arguments.args

        # Load smart modules
        self.smartmodules_loader = SmartModulesLoader(self.sqlsess, self.settings.services)

        # Context parameters are organized in dict 
        # { service : list of db objects }
        self.creds    = defaultdict(list)
        self.users    = defaultdict(list)
        self.products = defaultdict(list)
        self.options  = defaultdict(list)

        if args.creds:
            for c in args.creds:
                self.creds[c['service']].append(
                    Credential(type=c['auth_type'], 
                               username=c['username'], 
                               password=c['password']))
        if args.users:
            for u in args.users:
                self.users[c['service']].append(
                    Credential(type=u['auth_type'], 
                               username=u['username'], 
                               password=None))

        if args.products:
            for type_,name in args.products.items():
                service = self.settings.services.get_service_for_product_type(type_)
                if service:
                    self.products[service].append(
                        Product(type=type_,
                                name=name))

        if args.options:
            for name, value in args.options.items():
                service = self.settings.services.get_service_for_specific_option(name)
                if service:
                    self.options[service].append(
                        Option(name=name, 
                               value=value))

        # Attack configuration
        categories = self.settings.services.list_all_categories() # default: all

        if args.cat_only:
            categories = [ cat for cat in categories if cat in args.cat_only ]
        elif args.cat_exclude:
            categories = [ cat for cat in categories if cat not in args.cat_exclude ]

        # Run the attack
        self.attack_scope = AttackScope(self.settings, 
                                        self.arguments,
                                        ResultsRequester(self.sqlsess), 
                                        self.smartmodules_loader, 
                                        filter_categories=categories, 
                                        filter_checks=args.checks, 
                                        attack_profile=args.profile,
                                        fast_mode=args.fast_mode)

        begin = time.time()
        if args.target_ip_or_url:
            self.__run_for_single_target(args)
        else:
            self.__run_for_multi_targets(args)
            
        print()
        logger.info('Done. Time spent: {0} seconds'.format(time.time()-begin))


    def __run_for_single_target(self, args):
        """
        Run attack against a single target specified into args
        """
        
        req = ServicesRequester(self.sqlsess)
        mission = None

        # Get Mission if target must be added into a mission scope
        if args.add:
            mission = self.sqlsess.query(Mission).filter(Mission.name == args.add).first()
            if not mission:
                raise AttackException('The specified mission does not exist in the database. You should create it if needed')

        # Create new Service/Host objects (if service already exist, will be merged by ServicesRequester.add_target)
        service = Service(name = args.service,
                          port = int(args.target_port),
                          protocol = {'tcp': Protocol.TCP, 'udp': Protocol.UDP}.get(
                            self.settings.services.get_protocol(args.service)),
                          url = args.target_ip_or_url if args.target_mode == TargetMode.URL else '')
        host = Host(ip = args.target_ip_or_url if args.target_mode == TargetMode.IP else '') # Will be updated when initializing Target()
        host.services.append(service)

        # Update credentials and options if needed
        for c in self.creds[args.service]   : service.credentials.append(c)
        for u in self.users[args.service]   : service.credentials.append(u)
        for o in self.options[args.service] : service.options.append(o)

        # Initialize Target and check if reachable
        target = Target(service, self.settings.services)
        if args.disable_banner_grab:
            logger.info('Check if target is reachable...')
        else:
            logger.info('Check if target is reachable and grab banner using Nmap...')
        reachable = target.smart_check(grab_banner_nmap=not args.disable_banner_grab)

        if args.target_mode == TargetMode.IP:
            msg = 'Target {neg}reachable: host {ip} | port {port}/{proto} | service {service}'.format(
                neg     = 'not ' if not reachable else '',
                ip      = target.get_ip(),
                port    = target.get_port(),
                proto   = target.get_protocol(),
                service = target.get_service_name())
        else:
            msg = 'Target URL {url} is {neg}reachable'.format(
                url = target.get_url(),
                neg = 'not ' if not reachable else '')

        if reachable:
            service.up = True
            logger.success(msg)
        else: 
            raise AttackException(msg)

        # Commit new data into database if target must be added to a mission
        if mission:
            logger.info('Results from this attack will be saved under mission "{mission}" in database'.format(mission=mission.name))
            req.select_mission(mission.name)
            req.add_target(target)

        # Run the attack
        self.attack_scope.add_target(target)
        self.attack_scope.attack(reverse_dns = #TODO
            , grab_banner_nmap=#TODO)
            )


    def __run_for_multi_targets(self, args):
        """
        Run attack against multiple targets from the database
        """

        # Get Mission from which targets must be extracted
        mission = self.sqlsess.query(Mission).filter(Mission.name == args.mission).first()
        if mission:
            logger.info('Extracting targets from mission "{mission}" ...'.format(mission=mission.name))
        else:
            raise AttackException('Mission {mission} does not exist into the database'.format(mission=args.mission))

        # Initialize Services requester and add filter if provided
        requester = ServicesRequester(self.sqlsess)
        requester.select_mission(args.mission)
        if args.filters_combined:
            for filt in args.filter:
                logger.info('Applying filters on mission scope: {filter}'.format(filter=filt))
            if len(args.filter) > 1:
                logger.info('Logical or is applied between each filter')
            requester.add_filter(args.filters_combined)

        # Retrieve targeted services from database
        services = requester.get_results()
        if not services:
            raise AttackException('There is no matching service to target into the database')

        # Add each targeted service into Attack scope 
        logger.info('Checking if targets are reachable...')
        for service in services:
            # Update credentials and options if needed
            # TODO: case None for all
            for c in self.creds[service.name]   : service.credentials.append(c)
            for u in self.users[service.name]   : service.credentials.append(u)
            for o in self.options[service.name] : service.options.append(o)

            # Initialize Target 
            target = Target(service, self.settings.services)
            # check now performed in AttackScope !

            # Update info into database if needed
            #requester.add_target(target)

            self.attack_scope.add_target(target)

        self.attack_scope.attack(reverse_dns = #TODO
            , grab_banner_nmap=#TODO)
            )