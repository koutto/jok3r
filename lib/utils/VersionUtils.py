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
        if '*' in requirement:
            pattern = requirement.replace('.', '[.]').replace('*', '.*')
            return re.match(pattern, version_number) is not None
        elif requirement.startswith('<'):
            return LooseVersion(version_number) < LooseVersion(requirement[1:].strip())
        elif requirement.startswith('>'):
            return LooseVersion(version_number) > LooseVersion(requirement[1:].strip())
        elif requirement.startswith('<='):
            return LooseVersion(version_number) <= LooseVersion(requirement[2:].strip())
        elif requirement.startswith('>='):
            return LooseVersion(version_number) >= LooseVersion(requirement[2:].strip())
        else:
            return LooseVersion(version_number) == LooseVersion(requirement)