# -*- coding: utf-8 -*-
###
### Core > ContextChecker
###
from lib.utils.VersionUtils import VersionUtils

class ContextChecker:

    @staticmethod
    def check_boolean_option(option_value, req_context_value):
        """
        Check if the value of a specific option of type "boolean" is matching
        the required context.

        :param option_value: Value of specific option of type OptionType.BOOLEAN
        :param req_context_value: Different possibilities to return True:
            - None: No restriction on option_value,
            - Boolean (True/False): option_value must be equal to this boolean.

        :return: Boolean indicating if option_value matches the required context option

        Option      Context      Result (run ?)
        True        True         True
        False       True         False
        True        False        False
        False       False        True
        any         None         True
        """
        status  = req_context_value is None
        status |= option_value == req_context_value
        return status


    @staticmethod
    def check_list_option(option_value, req_context_value):
        """
        Check if the value of a specific option of type "list" is matching
        the required context.

        :param option_value: Value of specific option of type OptionType.LIST
        :param req_context_value: Different possibilities to return True:
            - None: No restriction on option_value,
            - 'undefined': option_value must be unset (i.e. option_value == None)
            - list of accepted values: option_value must have its value in this list

        :return: Boolean indicating if option_value matches the required context option

        Option      Context      Result
        None        val          False
        val1        val1,val2    True
        val1        val2,val3    False
        any         None         True  
        any         'undefined'  False
        None        'undefined'  True 
        """
        status  = req_context_value is None
        status |= option_value in req_context_value
        status |= req_context_value == ['undefined'] and option_value is None
        return status


    @staticmethod
    def check_var_option(option_value, req_context_value):
        """
        Check if the value of a specific option of type "var" is matching
        the required context.

        :param option_value: Value of specific option of type OptionType.VAR
        :param req_context_value: Different possibilities to return True:
            - None: No restriction on option_value,
            - False: option_value must be undefined (i.e. option_value == None)
            - True: option_value must be defined (containing any value)

        :return: Boolean indicating if option_value matches the required context option

        Option      Context     Result
        None        True        False
        non-empty   True        True
        None        False       True
        non-empty   False       False
        any         None        True  
        """
        status  = req_context_value is None
        status |= option_value is None and req_context_value == False
        status |= option_value is not None and req_context_value == True
        return status


    @staticmethod
    def check_product_option(option_value, req_context_value):
        """
        Check if the value of a specific option of type "product" is matching
        the required conttext.

        :param option_value: Value of specific option of type OptionType.PRODUCT
        :param req_context_value: Different possibilities to return True:
            - None: No restriction on option_value,
            - 'undefined': option_value must be unset (i.e. option_value == None)
            - list of accepted values: option_value must have its value in this list

        :return: Boolean indicating if option_value matches the required context option

        Possible contexts:
        vendor/product_name
        vendor/product_name|version_known
        vendor/product_name|7.*
        vendor/product_name|7.1.*
        vendor/product_name|>7.1
        vendor/product_name|<=7.0
        vendor/product_name|7.1.1   
        """

        status  = req_context_value is None
        status |= req_context_value == ['undefined'] and option_value is None
        if status: 
            return True

        if option_value:
            option_product_name, option_product_version = VersionUtils.extract_name_version(option_value)

            for req_product in req_context_value:
                req_product_name, req_product_version = VersionUtils.extract_name_version(req_product)

                if option_product_name.lower() == req_product_name.lower():
                    # When no constraint on the version number
                    status  = not req_product_version

                    # When the version must be specified but no restriction on its value
                    status |= req_product_version.lower() == 'version_known' and option_product_version

                    # When constraints on the version number
                    status |= VersionUtils.check_version_requirement(option_product_version, req_product_version)
                    
                    if status:
                        return True
        return False