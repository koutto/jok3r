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
        args = self.arguments.args
        self.creds = defaultdict(list)
        self.users = defaultdict(list)
        self.options = defaultdict(list)

        # Load smart modules
        self.smartmodules_loader = SmartModulesLoader(self.sqlsess, self.settings.services)

        # Initialize provided credentials
        if args.creds:
            for c in args.creds:
                self.creds[c['service']].append(Credential(type=c['auth_type'], username=c['username'], password=c['password']))

        # Initialize provided single usernames
        if args.users:
            for u in args.users:
                self.users[c['service']].append(Credential(type=u['auth_type'], username=u['username'], password=None))

        # Initialize provided context-specific options
        if args.specific:
            for option_name in args.specific:
                service = self.settings.services.get_service_for_specific_option(option_name)
                if service:
                    self.options[service].append(Option(name=option_name, value=args.specific[option_name]))

        # Run the attack
        self.attack_scope = AttackScope(self.settings, 
                                        ResultsRequester(self.sqlsess), 
                                        self.smartmodules_loader, 
                                        args.cat_only, 
                                        args.checks, 
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
        Run attack against a single target specified into argss
        """
        req = ServicesRequester(self.sqlsess)
        mission = None

        # Get Mission if target must be added into a mission scope
        if args.add:
            mission = self.sqlsess.query(Mission).filter(Mission.name == args.add).first()
            if not mission:
                raise AttackException('The specified mission does not exist in the database. You should create it if needed')

            # # Check if service is already present inside database
            # filter_ = Filter(FilterOperator.AND)
            # filter_.add_condition(Condition(args.service, FilterData.SERVICE_EXACT))
            # filter_.add_condition(Condition(args.target_port, FilterData.PORT))
            # filter_.add_condition(Condition(self.settings.services.get_protocol(args.service), FilterData.PROTOCOL))
            # filter_.add_condition(Condition(args.target_ip_or_url if args.target_mode == TargetMode.URL else '', FilterData.URL_EXACT))
            # try:
            #     req.add_filter(filter_)
            # except FilterException as e:
            #     raise AttackException(e)

            # service = req.get_first_result()
            # deported to ServicesRequester

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
        self.attack_scope.attack()


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
            for c in self.creds[service.name]   : service.credentials.append(c)
            for u in self.users[service.name]   : service.credentials.append(u)
            for o in self.options[service.name] : service.options.append(o)

            # Initialize Target and check if reachable
            target = Target(service, self.settings.services)
            service.up = target.smart_check(grab_banner_nmap=False)
            self.sqlsess.commit()

            msg = 'host {ip} | port {port}/{proto} | service {service}'.format(
                    ip      = target.get_ip(),
                    port    = target.get_port(),
                    proto   = target.get_protocol(),
                    service = target.get_service_name())
            if service.up:
                logger.success('Target reachable: ' + msg)
            else:
                logger.warning('Target not reachable (skipped): ' + msg)
                continue

            # Update info into database if needed
            #requester.add_target(target)

            self.attack_scope.add_target(target)

        self.attack_scope.attack()      
