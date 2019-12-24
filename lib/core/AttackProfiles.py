#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > AttackProfiles
###
from lib.output.Output import Output
from lib.utils.StringUtils import StringUtils

class AttackProfile:

    def __init__(self, name, description, checks):
        """
        Create an Attack Profile.

        :param str name: Name of the profile
        :param str description: Description of the profile
        :param dict(list(str)) checks: Lists of checks to run (order is important) for
            each services that are supported by the profile.
            E.g. checks = {'ftp': ['check1', 'check2'], 'mssql': ['check3']}
        """
        self.name = name
        self.description = description
        self.checks = checks


    def is_service_supported(self, service):
        """
        Check if the Attack Profile can be run against a given service

        :param str service: Service name
        :return: Result of check
        :rtype: bool
        """
        return service.lower() in self.checks


    def is_check_supported(self, service, check_name):
        """
        Check if the Attack Profile runs the specified check.

        :param str service: Service name for the check
        :param str check_name: Check name to look for
        :return: Result of check
        :rtype: bool
        """
        return (
            self.is_service_supported(service) and
            check_name in self.checks[service]
        )


    def get_checks_for_service(self, service):
        """
        Get the list of check names that must be applied for the given service.

        :param str service: Service name
        :return: List of check names
        :rtype: list(str)
        """
        return self.checks.get(service)


    def __repr__(self):
        return self.name


#----------------------------------------------------------------------------------------


class AttackProfiles:

    def __init__(self, profiles=list()):
        """
        """
        self.profiles = profiles


    #------------------------------------------------------------------------------------
    # Simple Operations

    def add(self, profile):
        """
        Add a new attack profile.

        :param AttackProfile profile: New profile to add
        :return: Status
        :rtype: bool
        """
        if self.get(profile.name):
            return False
        self.profiles.append(profile)
        return True


    def get(self, name):
        """ 
        Get attack profile by name.

        :param str name: Profile name to get
        :return: Attack profile if found, None otherwise
        :rtype: AttackProfile|None
        """
        for p in self.profiles:
            if p.name.lower() == name.lower():
                return p
        return None


    def get_profiles_for_check(self, service, check_name):
        """
        Get list of attack profiles that run the specified check.

        :param str service: Service name for the check
        :param str check_name: Check name to look for
        :return: List of attack profiles
        :rtype: list(str)
        """
        list_profiles = list()
        for attack_profile in self.profiles:
            if attack_profile.is_check_supported(service, check_name):
                list_profiles.append(attack_profile.name)
        return list_profiles


    def is_valid_profile_name(self, profile_name):
        """
        Check if a profile name is valid.

        :param str profile_name: Attack profile name to check
        :return: Status
        :rtype: bool
        """
        for attack_profile in self.profiles:
            if attack_profile.name == profile_name:
                return True
        return False


    #------------------------------------------------------------------------------------
    # Output Methods

    def show(self, filter_service=None):
        """
        Display information about supported attack profiles

        :param str filter_service: Service name to filter with (default: no filter)
        """

        data = list()
        columns = [
            'Profile',
            'Description',
        ]

        for p in self.profiles:
            #print(p.checks)
            if not filter_service or p.is_service_supported(filter_service):
                data.append([
                    Output.colored(p.name, attrs='bold'),
                    StringUtils.wrap(p.description, 120)
                ])

        if filter_service:
            service = 'for service {}'.format(filter_service.upper()) 
        else:
            service = ''
        Output.title1('Attack Profiles {service}'.format(service=service))
        Output.table(columns, data, hrules=False)

        if not filter_service:
            print
            Output.print('Run "info --attack-profiles <service>" to see the attack ' \
                'profiles supported for a given service.')

