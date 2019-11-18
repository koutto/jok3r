#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > ContextRequirements
###
from collections import defaultdict

from lib.core.Config import *
from lib.core.Constants import *
from lib.utils.VersionUtils import VersionUtils
from lib.output.Logger import logger


class ContextRequirements:
    """
    Each Command object is linked to a ContextRequirements object. 
    When running an attack, the target must comply with the requirements defined
    into this ContextRequirements object.

    Context requirements can be defined on:
    - Specific options: Available parameter(s) depend on the service (e.g. https for
      HTTP, webdav for HTTP, ftps for FTP, snmpv3 for SNMP, ...). 

    - Products: 
        Possible values:
        - None: no restriction on the product name (default),
        - str: restriction on a given product name,
        - list: restriction on several possible product names,
        - 'undefined': product must not be defined
        - 'any': product must be defined (any value)
        - 'any|version_known': product+version must be defined
        - 'any|version_unknown': product name must be known+version unknown

        When explicit requirement on the version number: perform version requirement 
        check only if version of product has been detected. Otherwise, we condider 
        it is better to perform the check anyway in order to avoid to miss stuff

        Available product type(s) depend on the service (e.g. web-server, web-cms...
        for HTTP).

        Accepted syntax examples:
            - For any supported product:
                - any
                - any|version_known
                - any|version_unknown

            - For a specific product:
                vendor/product_name (vendor/ is present only if needed)
                vendor/product_name|7.*
                vendor/product_name|7.1.*
                vendor/product_name|>7.1
                vendor/product_name|<=7.0
                vendor/product_name|7.1.1   
        
            - Inversion by prefixing with "!":
                !vendor/product_name
                ...

    - OS Family: Linux or Windows. This requirement is not excluding check when
      target's OS is unknown/undetected.

    - Authentication status ('auth_status'): Level of authentication on the service.
      Possible values are:
        - NO_AUTH   : No credentials are known
        - USER_ONLY : At least one username is known
        - POST_AUTH : Valid credentials (username+password) are known
        - None      : Any level (default)
      For HTTP, 'auth_status' must be used along with 'auth_type' to define for which
      kind of authentication on HTTP it should apply (e.g. jboss, tomcat, wordpress...).
      Indeed, several different authentications can be managed for HTTP.
    """

    def __init__(self, 
                 specific_options, 
                 products, 
                 osfamily, 
                 auth_status, 
                 auth_type=None, 
                 raw='<empty>'):
        """
        Construct ContextRequirements object from information parsed from config file.

        Note: by default, any context condition is None is not set.

        :param dict specific_options: Requirements on specific options values
            e.g. : { 'name': 'value' }
        :param dict products: Requirements on products names (+ potentially versions)
            e.g. : { 'type': 'vendor/product_name|>7.1'}
        :param str osfamily: Requirement on the OS family
        :param int auth_status: Level of authentication required on the service
        :param str auth_type: Authentication type (for HTTP only)
        :param str raw: Raw context requirements string as in .conf file (only
            for debugging purpose)
        """
        self.specific_options = defaultdict(lambda: None, specific_options) if \
            isinstance(specific_options, dict) else defaultdict(lambda: None)
        self.products = defaultdict(lambda: None, products) if \
            isinstance(products, dict) else defaultdict(lambda: None)
        self.osfamily = osfamily.lower() if osfamily else ''
        self.auth_status = auth_status
        self.auth_type = auth_type
        self.raw_string = raw
        self.is_empty = not self.specific_options \
                        and not self.products \
                        and not self.auth_status \
                        and not self.auth_type


    #------------------------------------------------------------------------------------
    # Target matching checkers

    def check_target_compliance(self, target):
        """
        Check if a target complies with context requirements

        :param Target target: Target to check
        :return: Result
        :rtype: bool
        """
        status = self.__is_target_matching_auth_status(target) and \
                 self.__is_target_matching_specific_options(target) and \
                 self.__is_target_matching_products(target) and \
                 self.__is_target_matching_osfamily(target)

        return status


    def __is_target_matching_auth_status(self, target):
        """
        Check if target complies with requirement on authentication level.

        :param Target target: Target to check
        :return: Result
        :rtype: bool  
        """
        if self.auth_status is None: 
            return True
        
        auth_type = self.auth_type if target.service.name == 'http' else None
        users_only = target.get_usernames_only(auth_type)
        userpass = target.get_userpass(auth_type)

        if len(userpass) > 0     : auth_level = POST_AUTH
        elif len(users_only) > 0 : auth_level = USER_ONLY
        else                     : auth_level = NO_AUTH 

        return auth_level == self.auth_status


    def __is_target_matching_specific_options(self, target):
        """
        Check if target complies with requirements on specific options values.

        :param Target target: Target to check
        :return: Result
        :rtype: bool 
        """
        status = True

        for opt in self.specific_options:
            type_ = target.services_config[target.service.name]['specific_options'][opt]
            val = target.get_specific_option_value(opt)

            if type_ == OptionType.BOOLEAN:
                status &= self.__check_specific_option_boolean(opt, val)
            elif type_ == OptionType.LIST:
                status &= self.__check_specific_option_list(opt, val)
            elif type_ == OptionType.VAR:
                status &= self.__check_specific_option_var(opt, val)

        return status


    def __is_target_matching_products(self, target):
        """
        Check if target complies with requirements on products names+version.

        :param Target target: Target to check
        :return: Result
        :rtype: bool
        """
        status = True

        for prodtype in self.products:
            # Get list of (product name, product version) for the current product type
            # that have been detected for the target
            target_products_name_version = target.get_products_name_version(prodtype)
            # name, version = target.get_product_name_version(prodtype)
            # # (None, None) when not product detected for this type

            status_prodtype = False
            for name, version in target_products_name_version:
                status_prodtype |= self.__check_product(prodtype, name, version)

            status &= status_prodtype

        return status


    def __is_target_matching_osfamily(self, target):
        """
        Check if target complies with requirements on OS family.

        :param Target target: Target to check
        :return: Result
        :rtype: bool
        """

        # OS requirement is excluding a check only when target's OS is known and there
        # is a defined requirement and they do not match
        if not target.get_os() or not self.osfamily:
            return True

        return (self.osfamily.lower() in target.get_os().lower())


    #------------------------------------------------------------------------------------
    # Unit checkers

    def __check_specific_option_boolean(self, name, val):
        """
        Check if the value of a specific option of type "boolean" complies with 
        requirements.

        Option value    Requirement     Result
        True            True            True
        False           True            False
        True            False           False
        False           False           True
        any             None            True

        :param str name: Specific option name
        :param str val: Specific option value to check
        :return: Result
        :rtype: bool
        """
        requirement = self.specific_options[name]

        status  = requirement is None
        status |= (val == requirement)

        return status


    def __check_specific_option_list(self, name, val):
        """
        Check if the value of a specific option of type "list" complies with
        requirements.

        Option value    Requirement     Result
        None            val             False
        val1            val1,val2       True
        val1            val2,val3       False
        any             None            True  
        any             'undefined'     False
        None            'undefined'     True

        :param str name: Specific option name
        :param str val: Specific option value to check
        :return: Result
        :rtype: bool
        """
        requirement = self.specific_options[name]

        status  = requirement is None
        status |= val in requirement
        status |= (requirement == ['undefined'] and val is None)

        return status


    def __check_specific_option_var(self, name, val):
        """
        Check if the value of a specific option of type "var" complies with
        requirements.

        Option value    Requirement     Result
        None            True            False
        non-empty       True            True
        None            False           True
        non-empty       False           False
        any             None            True  


        :param str name: Specific option name
        :param str val: Specific option value to check
        :return: Result
        :rtype: bool
        """
        requirement = self.specific_options[name]

        status  = requirement is None
        status |= (val is None and requirement == False)
        status |= (val is not None and requirement == True)

        return status


    def __check_product(self, prodtype, prodname, prodversion):
        """
        Check if a product of a given type complies with the requirements.

        Requirements can be based on:
            - the product name only,
            - the product name and version.

        Compliance checks on product names are following these rules:
        Product name    Requirement     Result
        None            val             False
        val1            val1,val2       True
        val1            val2,val3       False
        any             None            True  
        any             'undefined'     False
        None            'undefined'     True

        Examples of possible context requirements on versions:
        any
        any|version_known
        vendor/product_name
        vendor/product_name|version_known
        vendor/product_name|7.*
        vendor/product_name|7.1.*
        vendor/product_name|>7.1
        vendor/product_name|<=7.0
        vendor/product_name|7.1.1   

        :param str prodtype: Product type 
        :param str prodname: Product name to check (can be None)
        :param str prodversion: Product version number to check (can be None)
        """
        requirement = self.products[prodtype]

        status  = requirement is None
        status |= (requirement == ['undefined'] and prodname is None)
        if status: 
            return True

        try:
            if prodname:
                for req_prod in requirement:
                    req_prodname, req_prodvers = VersionUtils.extract_name_version(req_prod)
                    logger.debug('Required product: type={}, name={}, version={}'.format(
                        prodtype, req_prodname, req_prodvers))
                    logger.debug('Target product: type={}, name={}, version={}'.format(
                        prodtype, prodname, prodversion))

                    # Handle case where prefixed with "!" for inversion
                    if len(req_prodname) > 0 and req_prodname[0] == '!':
                        inversion = True
                        req_prodname = req_prodname[1:]
                    else:
                        inversion = False

                    # When no special requirement on vendor/product_name but must be known
                    if req_prodname.lower() == 'any':
                        # When version can be unknown
                        status  = not req_prodvers

                        # When the version must be known (any value)
                        status |= (req_prodvers.lower() == 'version_known' and \
                            prodversion != '')

                        # When the version is unknown
                        status |= (req_prodvers.lower() == 'version_unknown' and \
                            prodversion == '')

                    # When requirement on a defined vendor/product_name and it is matching
                    elif req_prodname.lower() == prodname.lower():

                        # When no requirement on the version number
                        status  = not req_prodvers

                        # When the version must be known but no requirement on its value
                        # status |= (req_prodvers.lower() == 'version_known' \
                        #     and prodversion != '')

                        # # When the version is unknown
                        # status |= (req_prodvers.lower() == 'version_unknown' and \
                        #     prodversion == '')

                        # When explicit requirement on the version number 
                        # Perform version requirement check only if version of product
                        # has been detected. Otherwise, we condider it is better to 
                        # perform the check anyway in order to avoid to miss stuff
                        status |= (prodversion != '' and \
                            VersionUtils.check_version_requirement(
                                prodversion, req_prodvers))

                    if inversion and not status:
                        return True

                    if status:
                        return True
        except Exception as e:
            logger.error('An error occured when checking product requirements: {}'.format(e))
            logger.error('Following requirements syntax should be reviewed: {}'.format(
                requirement))
            logger.warning('Product requirements are ignored for this check')
            return True
        return False


    #------------------------------------------------------------------------------------
    # Output methods

    def __repr__(self):
        """Print context requirements in dict style"""
        return self.raw_string
        
        # requirements = dict()
        # for o in self.specific_options:
        #     requirements[o] = self.specific_options[o]
        # for p in self.products:
        #     requirements[p] = self.products[p]
        # if self.auth_status:
        #     requirements['auth_status'] = self.auth_status
        # if self.auth_type:
        #     requirements['auth_type'] = self.auth_type

        # return str(requirements)
