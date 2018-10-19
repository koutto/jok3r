# -*- coding: utf-8 -*-
###
### Core > Tool
###
import os
import subprocess
import sys

from lib.utils.FileUtils import FileUtils
from lib.utils.CLIUtils import CLIUtils
from lib.utils.StringUtils import StringUtils
from lib.core.ProcessLauncher import ProcessLauncher
from lib.core.Command import Command
from lib.core.Config import *
from lib.core.Exceptions import SettingsException
from lib.output.Output import Output
from lib.output.Logger import logger


class Tool:

    def __init__(self, 
                 name_clean,
                 name_display,
                 description,
                 target_service,
                 installed,
                 last_update,
                 install_command,
                 update_command,
                 check_command):
        """
        :param name_clean: Name of the tool without special characters (mandatory)
        :param name_display: Name of the tool to display (mandatory)
        :param description: Description of the tool (mandatory)
        :param target_service: Service targeted by the tool, "multi" when supporting various services (mandatory)
        :param installed: Boolean indicating if tool is installed (mandatory)
        :param last_update: Datetime of last update, empty if not installed (mandatory)
        :param install_command: Instance of Command embedding tool installation command-line (optional)
        :param update_command: Instance of Command embedding tool update command-line (optional)
        :param check_command: Instance of Command embedding command-line for checking install (optional)
        """
        self.name_clean      = name_clean
        self.name_display    = name_display
        self.description     = description
        self.target_service  = target_service
        self.installed       = installed if isinstance(installed, bool) else False
        self.last_update     = last_update
        self.install_command = install_command
        self.update_command  = update_command
        self.check_command   = check_command
        self.tool_dir        = FileUtils.absolute_path('{toolbox}/{service}/{name}'.format(
                                    toolbox  = TOOLBOX_DIR,
                                    service  = self.target_service,
                                    name     = self.name_clean)) if self.install_command else ''


    def install(self, settings, fast_mode=False):
        """
        Install the tool
        :param settings: Settings instance
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: Boolean indicating install status
        """
        if not self.__check_pre_install(settings, fast_mode): return False
        if self.install_command:
            if not self.__create_tool_dir(): return False
            if not self.__run_install_update(fast_mode): return False
        return self.__check_post_install_update(settings, fast_mode)


    def update(self, settings, fast_mode=False):
        """
        Update the tool
        :param settings: Settings instance
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: Boolean indicating update status
        """
        if not self.__check_pre_update(settings, fast_mode): return False
        if self.update_command:
            if not self.__run_install_update(fast_mode, update=True): return False
        return self.__check_post_install_update(settings, fast_mode, update=True)


    def remove(self, settings):
        """
        Remove the tool:
            - Remove tool directory into toolbox
            - Change install status to false
        :param settings: Settings instance
        :return: Boolean indicating removal status
        """
        # Delete tool directory if tool was installed inside toolbox/...
        if self.install_command:
            if not FileUtils.is_dir(self.tool_dir):
                logger.warning('Directory "{dir}" does not exist'.format(dir=self.tool_dir))
                return False
            elif not FileUtils.remove_directory(self.tool_dir):
                logger.error('Unable to delete directory "{dir}". Check permissions and/or re-run with sudo'.format(
                    dir=self.tool_dir))
                return False
            else:
                logger.success('Tool directory "{dir}" deleted'.format(dir=self.tool_dir))

        # Make sure "installed" option in config file is set to False
        if settings.change_installed_status(self.target_service, self.name_clean, install_status=False):
            logger.success('Tool marked as uninstalled')
        else:
            logger.error('An unexpected error occured when trying to mark the tool as uninstalled !')
            return False

        self.installed = False
        return True


    def show_tool(self):
        """
        TODO
        """
        pass


    def __check_pre_install(self, settings, fast_mode):
        """
        Checks to run before installing the tool
        :param settings: Settings instance
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: Boolean indicating status
        """
        if self.installed:
            logger.info('{tool} is already installed (according to settings), skipped'.format(tool=self.name_display))
            return False

        elif not self.install_command:
            logger.warning('The tool {tool} has no installation command specified in config file'.format(
                tool=self.name_display))
            if fast_mode or Output.prompt_confirm('Is the tool already installed on your system ?', default=True):
                try:
                    if settings.change_installed_status(self.target_service, self.name_clean, True):
                        logger.success('Tool {tool} has been marked as installed in settings'.format(tool=self.name_display))
                        return True
                    else:
                        logger.error('Error when saving the configuration file "{filename}{ext}"'.format(
                            filename=INSTALL_STATUS_CONF_FILE, ext=CONF_EXT))
                        return False
                except SettingsException as e:
                    logger.error(e)
                    self.remove(settings)
                    return False
            else:
                logger.info('Tool {tool} is still not marked as installed in settings'.format(tool=self.name_display))
            return False

        return True


    def __check_pre_update(self, settings, fast_mode):
        """
        Checks to run before updating the tool
        :param settings: Settings instance
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: Boolean indicating status
        """
        if not self.installed:
            logger.info('{tool} is not installed yet (according to settings), skipped'.format(tool=self.name_display))
            return False

        elif not self.update_command:
            logger.warning('No tool update command specified in config file, skipped.')
            return False

        # Create directory for the tool if necessary (should not be necessary because only update)
        if self.install_command and not FileUtils.is_dir(self.tool_dir):
            logger.warning('Tool directory does not exist but tool marked as installed. Trying to re-install it...')
            return self.install(settings, fast_mode)

        return True


    def __run_install_update(self, fast_mode, update=False):
        """
        Run install/update command
        :param update: Mode selector, True for update | False for install (default)
        :return: Boolean indicating status
        """
        if update : cmd = self.update_command.get_cmdline(self.tool_dir)
        else      : cmd = self.install_command.get_cmdline(self.tool_dir)

        mode = 'update' if update else 'install'

        logger.info('Description: {descr}'.format(descr=self.description))
        #Output.print('{mode} command : {cmd}'.format(mode=mode.capitalize(), cmd=cmd_short))
        if fast_mode or Output.prompt_confirm('Confirm {mode} ?'.format(mode=mode), default=True):
            Output.begin_cmd(cmd)
            ProcessLauncher(cmd).start()
            Output.delimiter()
            logger.success('Tool {mode} has finished'.format(mode=mode))
            return True
        else:
            logger.warning('Tool {mode} aborted'.format(mode=mode))
            return False


    def __check_post_install_update(self, settings, fast_mode, update=False):
        """
        Post-install/update checks
        :param settings: Settings instance
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: Boolean indicating status
        """
        mode = ('update','updated') if update else ('install','installed')
        status = True

        if not fast_mode:
            if not self.check_command:
                logger.info('No check_command defined in settings for {tool}, will assume it is ' \
                'correctly {mode}'.format(tool=self.name_display, mode=mode[1]))
            else:
                logger.info('Now, checking if {tool} has been {mode} correctly. Hit any key to run test...'.format(
                    tool=self.name_display, mode=mode[1]))
                CLIUtils.getch()
                status = self.__run_check_command()

        # Change install status in configuration file
        if status:
            try:
                if settings.change_installed_status(self.target_service, self.name_clean, install_status=True):
                    logger.success('Tool {tool} has been marked as successfully {mode}'.format(
                        tool=self.name_display, mode=mode[1]))
                    return True
                else:
                    logger.error('Error when updating configuration file "{filename}{ext}"'.format(
                        filename=INSTALL_STATUS_CONF_FILE, ext=CONF_EXT))
                    return False
            except SettingsException as e:
                logger.error('An unexpected error occured when trying to mark the tool as {mode}: ' \
                    '{exception}'.format(exception=e, mode=mode[1]))
                if not update:
                    self.remove(settings)
                return False
        else:
            logger.warning('Tool {tool} has not been marked as {mode}'.format(
                tool=self.name_display, mode=mode[1]))
            if not update:
                self.remove(settings)
            else:
                if not fast_mode and Output.prompt_confirm('Do you want to try to re-install ?', default=True):
                    return self.__reinstall(settings, fast_mode)
            return False


    def __reinstall(self, settings, fast_mode):
        """
        Try to re-install the tool, ie. remove and install
        :param settings: Settings instance
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return: Boolean indicating status
        """
        logger.info('First, the tool directory will be removed...')
        if not self.remove(settings):
            return False
        logger.info('Now, running a new install for {tool}...'.format(tool=self.name_display))
        return self.install(settings)


    def __run_check_command(self):
        """
        Run the check command. The goal is to quickly check if the tool is not buggy or
        missing some dependencies
        :return: Boolean indicating if tool is correctly installed
        """
        logger.info('Running the check command for the tool {tool}...'.format(tool=self.name_display))
        cmd = self.check_command.get_cmdline(self.tool_dir)

        Output.begin_cmd(cmd)
        ProcessLauncher(cmd).start()
        Output.delimiter()

        return Output.prompt_confirm('Does the tool {tool} seem to be running correctly ?'.format(
            tool=self.name_display), default=True) 


    def __create_tool_dir(self):
        """
        Create the tool directory if necessary
        :return: Boolean indicating status
        """
        if self.tool_dir:
            if FileUtils.is_dir(self.tool_dir):
                logger.info('Directory "{dir}" already exists'.format(dir=self.tool_dir))
                return True

            try:
                FileUtils.create_directory(self.tool_dir)
            except Exception as e:
                logger.error('Unable to create new directory "{dir}": {exception}'.format(
                    dir=self.tool_dir, exception=e))
                return False
            logger.info('New directory "{dir}" created'.format(dir=self.tool_dir))
            return True
        else:
            return False






    # def printToolSummary(self, output):
    #   """
    #   Print tool info nicely
    #   """

    #   output.title2('   {0} {1}'.format(self.name, '[-> {0}]'.format(self.tool_ref_name) if self.tool_ref_name else ''))
    #   output.printN('     Description : {0}'.format(self.description))
    #   #if self.command:       output.printN('     Command     : {0}'.format(self.command.cmdline))
    #   output.printRaw('     Installed   : ')   
    #   last_update = self.last_update if self.last_update else 'Unknown'
    #   output.printGreen('Yes [last update: {0}]\n'.format(last_update)) if self.installed else output.printRed('No\n')
    #   if self.installed:  output.printN('     Location    : {0}'.format(self.tool_dir))
    #   if self.specific_options:
    #       specific = ''
    #       for option in self.specific_options:
    #           t, val = SPECIFIC_OPTIONS[self.service_name][option], self.specific_options[option]
    #           if t == OptionType.BOOLEAN and val == True:
    #               specific += '         - {0}: True\n'.format(option)
    #           elif t == OptionType.LIST and val:
    #               specific += '         - {0}: {1}\n'.format(option, ', '.join(value_opt))
    #           elif t == OptionType.VAR and val == True:
    #               specific += '         - {0}: True (var must be set)\n'.format(option)
    #       if specific:
    #           output.printRaw('     Specific    :\n{0}'.format(specific))


    # def printToolSummaryBrief(self, output):
    #   """
    #   Print tool name + install status on one line
    #   """
    #   txt = '   - {0}{1}\n'.format(self.name, ' [-> {0}]'.format(self.tool_ref_name) if self.tool_ref_name else '')
    #   output.printGreen(txt) if self.installed else output.printRed(txt)

















