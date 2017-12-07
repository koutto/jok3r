import Constants


class SpecificOptions(object):

    @staticmethod
    def listAvailableSpecificOptions(settings, service, output):
        """
        Print list of available specific option for the given service
        2 kinds of options are possible:
            - Boolean option (true/false) ; eg. ssl_specific
            - List member. Different members are displayed
        @Args       settings:   Settings instance
                    service:    The selected service name
                    output:     Instance of CLIOutput
        @Returns    None
        """
        if service not in settings.general_settings.keys():
            return      

        string = ''
        for option in Constants.SPECIFIC_TOOL_OPTIONS[service]:
            if SpecificOptions.specificOptionType(service, option) == 'boolean':
                string += output.boldString('   - {0} \t: [Boolean]\n'.format(option))
            else:
                string += output.boldString('   - {0} \t: [List member]\n'.format(option))
                for value in SpecificOptions.getListValues(settings, service, option):
                    string += '      +-- {0}\n'.format(value)

        if string:
            output.printInfo('Available specific options for service {0}:'.format(service))
            output.printRaw(string)
        else:
            output.printInfo('No specific option for service {0}'.format(service))


    @staticmethod
    def specificOptionType(service, option):
        """
        Returns option type
        @Args       service:    the selected service
                    option:     the specific option
        @Returns    the type 'boolean' / 'list_member'
        """
        if not Constants.SPECIFIC_TOOL_OPTIONS[service][option]:
            return 'boolean'
        else:
            return 'list_member'


    @staticmethod
    def isMemberOfList(settings, service, option, value):
        """
        Determine a value given for a specific option is valid or not (list member)
        @Args       service:    the selected service
                    option:     the specific option
                    value:      the value to check is valid
        @Returns    Boolean
        """
        return (value in settings.general_settings[service][Constants.SPECIFIC_TOOL_OPTIONS[service][option]])


    @staticmethod
    def getListValues(settings, service, option):
        """
        Print list of possible values for a given option name
        @Args       service:    the selected service
                    option:     the option name (must be type "list_member")
        @Return     str
        """
        if SpecificOptions.specificOptionType(service, option) != 'list_member':
            return 
        return settings.general_settings[service][Constants.SPECIFIC_TOOL_OPTIONS[service][option]]