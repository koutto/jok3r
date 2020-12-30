#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > VersionUtils
###
import re
from distutils.version import LooseVersion


class VersionUtils:

    @staticmethod
    def extract_name_version(full_name, delim='|'):
        """
        Extract name and version separately from a syntax [name][delim][version]
        """
        name = full_name[:full_name.index(delim)] if delim in full_name else full_name
        version = full_name[full_name.index(delim)+1:] if delim in full_name else ''
        return name, version


    @staticmethod
    def extract_vendor_name_version(full_name, delim1='/', delim2='|'):
        """
        Extract vendor, name and version separately from a syntax
        [vendor][delim1][name][delim2][version]
        """
        vendor = full_name[:full_name.index(delim1)] if delim1 in full_name else ''
        name, version = VersionUtils.extract_name_version(
            full_name[full_name.index(delim1)+1:] if delim1 in full_name else full_name,
            delim=delim2)
        return vendor, name, version


    @staticmethod
    def check_version_requirement(version_number, requirement):
        """
        Check if a version number matches requirements

        :param version_number: The version number to check
        :param requirement: Version requirements. Accepted syntax:
            - *
            - 7.*
            - 7.1.*
            - >7.1
            - <=7.0
            - 7.1.1
        """
        if not requirement:
            return True

        # When the version must be known but no requirement on its value
        elif requirement.lower() == 'version_known':
            return (version_number != '')
        # When the version is unknown
        elif requirement.lower() == 'version_unknown':
            return (version_number == '')

        elif '*' in requirement:
            pattern = requirement.replace('.', '[.]').replace('*', '.*')
            return re.match(pattern, version_number) is not None
        elif requirement.startswith('<='):
            return LooseVersion(version_number) <= LooseVersion(requirement[2:].strip())
        elif requirement.startswith('>='):
            return LooseVersion(version_number) >= LooseVersion(requirement[2:].strip())
        elif requirement.startswith('<'):
            return LooseVersion(version_number) < LooseVersion(requirement[1:].strip())
        elif requirement.startswith('>'):
            return LooseVersion(version_number) > LooseVersion(requirement[1:].strip())
        else:
            print(version_number)
            print(requirement)
            return LooseVersion(version_number) == LooseVersion(requirement)


    @staticmethod
    def is_version_more_accurate(old_version, new_version):
        """
        Check if a new found version number is more accurate than an old known one
        Examples:
            - old: 7.0 -> new: 7.0.36 = True
            - old: 5.0 -> new: 5.0.0  = True
            - old: 4.2.3 -> new: 4.2  = False
            - old: 4.0.1 -> new: 4.2  = False

            Change of major version number is always taken into account:
            - old: 1.0.0 -> new: 4.2 = True
        """
        old = LooseVersion(old_version)
        new = LooseVersion(new_version)
        if len(str(new)) == 0:
            return False
        if len(str(old)) == 0:
            return False
        
        try:
            old_major = int(str(old)[0])
            new_major = int(str(new)[0])
        except:
            return False

        if new_major != old_major:
            return True
        else:
            return (len(str(new)) >= len(str(old)))
