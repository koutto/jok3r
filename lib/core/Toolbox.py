#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Toolbox
###
"""
File tree for the toolbox:
--------------------------

toolbox/
  +-- target_service_01/
      +-- tool_name_01/
      +-- tool_name_02/
      ...
  +-- target_service_02/
  ...
"""
import os
from collections import OrderedDict

from lib.core.Config import *
from lib.utils.FileUtils import FileUtils
from lib.utils.OrderedDefaultDict import OrderedDefaultDict
from lib.utils.StringUtils import StringUtils
from lib.output.Output import Output
from lib.output.Logger import logger


class Toolbox:

    def __init__(self, settings, services):
        """
        Construct the Toolbox object.

        :param Settings settings: Settings from config file
        :param list services: Supported services (including special service "multi")
        """
        self.settings = settings
        self.services = services
        # Organize tools in dict {service: [tools]}
        self.tools    = OrderedDefaultDict(list, {k:[] for k in services})


    #------------------------------------------------------------------------------------
    # Dict-like accessors for self.tools

    def __getitem__(self, key):
        return self.tools[key]

    def __setitem__(self, key, value):
        self.tools[key] = value

    def __delitem__(self, key):
        del self.tools[key]

    def __contains__(self, key):
        return key in self.tools

    def __len__(self):
        return len(self.tools)

    def __repr__(self):
        return repr(self.tools)

    def keys(self):
        return self.tools.keys()

    def values(self):
        return self.tools.values()


    #------------------------------------------------------------------------------------
    # Basic Operations

    def add_tool(self, tool):
        """
        Add a tool into the toolbox.

        :param Tool tool: Tool to add
        :return: Status
        :rtype: bool
        """
        if tool.target_service not in self.services: 
            return False
        self.tools[tool.target_service].append(tool)
        return True


    def get_tool(self, tool_name):
        """
        Retrieve a tool by its name from toolbox.
        NOT case-sensitive search.

        :param str tool_name: The name of the tool to get
        :return: Tool if found, None otherwise
        :rtype: Tool|None
        """
        for service in self.services:
            for tool in self.tools[service]:
                if tool_name.lower() == tool.name.lower():
                    return tool
        return None


    def nb_tools(self, filter_service=None, only_installed=False):
        """
        Get the number of tools inside the toolbox - installed of not - that target
        either a given service or all services.

        :param str filter_service: Service name to filter with (default: no filter)
        :param bool only_installed: Set to true to count only installed tools
        :return: Number of tools targeting either the given service or all services
        :rtype: int
        """
        if filter_service is not None and filter_service not in self.services: 
            return 0

        nb = 0
        services = self.services if filter_service is None else [filter_service]
        for service in services:
            for tool in self.tools[service]:
                if only_installed:
                    if tool.installed:
                        nb += 1
                else:
                    nb += 1
        return nb


    #------------------------------------------------------------------------------------
    # Install 

    def install_all(self, fast_mode=False):
        """
        Install all tools in the toolbox.

        :param bool fast_mode: Set to true to disable prompts and install checks
        """
        for service in self.services:
            self.install_for_service(service, fast_mode=fast_mode)


    def install_for_service(self, service, fast_mode=False):
        """
        Install the tools for a given service.

        :param str service: Name of the service targeted by the tools to install 
            (may be "multi")
        :param bool fast_mode: Set to true to disable prompts and install checks
        """
        if service not in self.services: 
            return

        Output.title1('Install tools for service: {service}'.format(service=service))

        if not self.tools[service]:
            logger.info('No tool specific to this service in the toolbox')
        else:
            i = 1
            for tool in self.tools[service]:
                if i>1: print()
                Output.title2('[{i:02}/{max:02}] Install {tool_name}:'.format(
                    i         = i,
                    max       = len(self.tools[service]),
                    tool_name = tool.name))

                tool.install(self.settings, fast_mode=fast_mode)
                i += 1 


    #------------------------------------------------------------------------------------
    # Update

    def update_all(self, fast_mode=False):
        """
        Update all tools in the toolbox.

        :param bool fast_mode: Set to true to disable prompts and install checks
        """
        for service in self.services:
            self.update_for_service(service, fast_mode=fast_mode)


    def update_for_service(self, service, fast_mode=False):
        """
        Update the tools for a given service.

        :param str service: Name of the service targeted by the tools to update 
            (may be "multi")
        :param bool fast_mode: Set to true to disable prompts and install checks
        """
        if service not in self.services: return
        Output.title1('Update tools for service: {service}'.format(service=service))

        i = 1
        for tool in self.tools[service]:
            if i>1: print()
            Output.title2('[{i:02}/{max:02}] Update {tool_name}:'.format(
                i         = i,
                max       = len(self.tools[service]),
                tool_name = tool.name))

            tool.update(self.settings, fast_mode=fast_mode)
            i += 1


    #------------------------------------------------------------------------------------
    # Remove

    def remove_all(self):
        """Remove all tools in the toolbox."""
        for service in self.services:
            self.remove_for_service(service)


    def remove_for_service(self, service):
        """
        Remove the tools for a given service.

        :param str service: Name of the service targeted by the tools to remove
            (may be "multi")
        """
        if service not in self.services: return
        Output.title1('Remove tools for service: {service}'.format(service=service))

        i = 1
        status = True
        for tool in self.tools[service]:
            if i>1: print()
            Output.title2('[{i:02}/{max:02}] Remove {tool_name}:'.format(
                i         = i,
                max       = len(self.tools[service]),
                tool_name = tool.name))

            status &= tool.remove(self.settings)
            i += 1

        # Remove the service directory if all tools successfully removed
        if status:
            short_svc_path = '{toolbox}/{service}'.format(toolbox=TOOLBOX_DIR, 
                                                          service=service)

            full_svc_path = FileUtils.absolute_path(short_svc_path)

            if FileUtils.remove_directory(full_svc_path):
                logger.success('Toolbox service directory "{path}" deleted'.format(
                    path=short_svc_path))
            else:
                logger.warning('Toolbox service directory "{path}" cannot be deleted ' \
                    'because it still stores some files'.format(path=short_svc_path))


    def remove_tool(self, tool_name):
        """
        Remove one tool from the toolbox.

        :param str tool_name: Name of the tool to remove
        :return: Status of removal
        :rtype: bool
        """
        tool = self.get_tool(tool_name)
        if not tool:
            logger.warning('No tool with this name in the toolbox')
            return False
        else:
            return tool.remove(self.settings)


    #------------------------------------------------------------------------------------
    # Output Methods

    def show_toolbox(self, filter_service=None):
        """
        Display a table showing the content of the toolbox.

        :param str filter_service: Service name to filter with (default: no filter)
        """
        if filter_service is not None and filter_service not in self.services: 
            return

        data = list()
        columns = [
            'Name',
            'Service',
            'Status/Update',
            'Description',
        ]

        services = self.services if filter_service is None else [filter_service] 
        for service in services:
            for tool in self.tools[service]:

                # Install status style
                if tool.installed:
                    status = Output.colored('OK | '+tool.last_update.split(' ')[0], 
                        color='green')
                else:
                    status = Output.colored('Not installed',  color='red')

                # Add line for the tool
                data.append([
                    tool.name,
                    tool.target_service,
                    status,
                    StringUtils.wrap(tool.description, 120), # Max line length
                ])

        Output.title1('Toolbox content - {filter}'.format(
            filter='all services' if filter_service is None \
                   else 'service ' + filter_service))

        Output.table(columns, data, hrules=False)


