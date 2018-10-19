# -*- coding: utf-8 -*-
###
### Core > Toolbox
###
#
# File tree for the toolbox:
# --------------------------
#
# toolbox/
#   +-- target_service_01/
#       +-- tool_name_01/
#       +-- tool_name_02/
#       ...
#   +-- target_service_02/
#   ...
#
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
        self.settings = settings
        self.services = services
        self.tools    = OrderedDefaultDict(list, {k:[] for k in services})

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


    def add_tool(self, tool):
        """
        Add a Tool into the toolbox
        :param tool: Tool instance
        :return: Boolean indicating status
        """
        if tool.target_service not in self.services: return False
        self.tools[tool.target_service].append(tool)
        return True


    def get_tool(self, tool_name):
        """
        Retrieve a Tool from toolbox
        :param tool_name: The name of the tool
        :return: Tool instance if found, None otherwise
        """
        for service in self.services:
            for tool in self.tools[service]:
                if tool_name.lower() in (tool.name_clean.lower(), tool.name_display.lower()):
                    return tool
        return None


    def install_toolbox_full(self, fast_mode=False):
        """
        Install the full toolbox
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: None
        """
        for service in self.services:
            self.install_toolbox_service(service, fast_mode=fast_mode)


    def install_toolbox_service(self, service, fast_mode=False):
        """
        Install the tools for a given service
        :param service: Name of the service targeted by the tools to install (may be "multi")
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: None
        """
        if service not in self.services: return
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
                    tool_name = tool.name_display))
                tool.install(self.settings, fast_mode=fast_mode)
                i += 1 


    def update_toolbox_full(self, fast_mode=False):
        """
        Update the full toolbox
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: None
        """
        for service in self.services:
            self.update_toolbox_service(service, fast_mode=fast_mode)


    def update_toolbox_service(self, service, fast_mode=False):
        """
        Update the tools for a given service
        :param service: Name of the service targeted by the tools to update (may be "multi")
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: None
        """
        if service not in self.services: return
        Output.title1('Update tools for service: {service}'.format(service=service))
        i = 1
        for tool in self.tools[service]:
            if i>1: print()
            Output.title2('[{i:02}/{max:02}] Update {tool_name}:'.format(
                i         = i,
                max       = len(self.tools[service]),
                tool_name = tool.name_display))
            tool.update(self.settings, fast_mode=fast_mode)
            i += 1


    def remove_toolbox_full(self):
        """
        Remove the full toolbox
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: None
        """
        for service in self.services:
            self.remove_toolbox_service(service)


    def remove_toolbox_service(self, service):
        """
        Remove the tools for a given service
        :param service: Name of the service targeted by the tools to remove (may be "multi")
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: None
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
                tool_name = tool.name_display))
            status &= tool.remove(self.settings)
            i += 1
        if status:
            service_dir = FileUtils.absolute_path('{toolbox}/{service}'.format(
                            toolbox  = TOOLBOX_DIR,
                            service  = service))
            if FileUtils.remove_directory(service_dir):
                logger.success('Toolbox service directory "{toolbox}/{service}" deleted'.format(
                    toolbox  = TOOLBOX_DIR,
                    service  = service))
            else:
                logger.warning('Toolbox service directory "{toolbox}/{service}" cannot be deleted ' +
                    'because it still stores some files'.format(
                    toolbox  = TOOLBOX_DIR,
                    service  = service))


    def remove_tool(self, tool_name):
        """
        Remove the given tool from toolbox
        """
        tool = self.get_tool(tool_name)
        if not tool:
            logger.warning('No tool with this name in the toolbox')
            return False
        else:
            return tool.remove(self.settings)


    def show_toolbox(self, filter_service=None):
        """
        Show the content of the toolbox
        :param filter_service: Service name. If specified, only show the content for the given service
        :return: None
        """
        if filter_service is not None and filter_service not in self.services: return
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
                status = Output.colored('OK | '+tool.last_update.split(' ')[0], color='green') if tool.installed else \
                         Output.colored('Not installed',  color='red')
                data.append([
                    tool.name_display,
                    tool.target_service,
                    status,
                    StringUtils.wrap(tool.description, 120),
                ])

        Output.title1('Toolbox content - {filter}'.format(
            filter='all services' if filter_service is None else 'service ' + filter_service))
        Output.table(columns, data, hrules=False)


    def nb_tools(self, filter_service=None):
        """
        Get the number of tools inside the toolbox - installed of not - either globally
        or only for a given service
        :param filter_service: Service name. If specified, only count for the given service
        :return: Number of tools
        """
        if filter_service is not None and filter_service not in self.services: return 0

        nb = 0
        services = self.services if filter_service is None else [filter_service]
        for service in services:
            nb += len(self.tools[service])
        return nb


    def nb_tools_installed(self, filter_service=None):
        """
        Get the number of tools installed, either globally (in the whole toolbox) or
        only for a given service
        :param filter_service: Service name. If specified, only count for the given service
        :return: Number of installed tools
        """
        if filter_service is not None and filter_service not in self.services: return 0

        nb = 0
        services = self.services if filter_service is None else [filter_service]
        for service in services:
            for tool in self.tools[service]:
                if tool.installed:
                    nb += 1
        return nb
