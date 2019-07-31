#!/usr/bin/env python3
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
                 name,
                 description,
                 target_service,
                 installed,
                 last_update='',
                 install_command=None,
                 update_command=None,
                 check_command=None):
        """
        Construct the Tool object.

        :param str name: Name of the tool ([a-zA-Z0-9-_])
        :param str description: Short description of the tool
        :param str target_service: Name of service targeted by this tool
            (might be "multi" for tools that could be used against various services)
        :param bool installed: Install status
        :param str last_update: Datetime of the last updated ('' if not installed)
        :param Command install_command: Install command (optional)
        :param Command update_command: Update command (optional)
        :param Command check_command: Command to check install (optional)
        """
        self.name            = name
        self.description     = description
        self.target_service  = target_service
        self.installed       = installed if isinstance(installed, bool) else False
        self.last_update     = last_update
        self.install_command = install_command
        self.update_command  = update_command
        self.check_command   = check_command
        self.tool_dir        = FileUtils.absolute_path(
            '{toolbox}/{service}/{name}'.format(
                toolbox  = TOOLBOX_DIR,
                service  = self.target_service,
                name     = self.name)) if self.install_command else ''


    #------------------------------------------------------------------------------------
    # Operations

    def install(self, settings, fast_mode=False):
        """
        Install the tool.

        :param Settings settings: Settings from config files
        :param bool fast_mode: Set to true to disable prompts
        :return: Install status
        :rtype: bool
        """
        if not self.__check_pre_install(settings, fast_mode): return False
        if self.install_command:
            if not self.__create_tool_dir(): return False
            if not self.__run_install_update(fast_mode): return False
        return self.__check_post_install_update(settings, fast_mode)


    def update(self, settings, fast_mode=False):
        """
        Update the tool.

        :param Settings settings: Settings from config files
        :param bool fast_mode: Set to true to disable prompts
        :return: Update status
        :rtype: bool
        """
        if not self.__check_pre_update(settings, fast_mode): return False
        if self.update_command:
            if not self.__run_install_update(fast_mode, update=True): return False
        return self.__check_post_install_update(settings, fast_mode, update=True)


    def remove(self, settings):
        """
        Remove the tool:
            - Remove tool directory into toolbox
            - Change install status to false.

        :param Settings settings: Settings from config files
        :return: Removal status
        :rtype: bool
        """

        # Delete tool directory if tool was installed inside toolbox directory
        if self.install_command:
            if not FileUtils.is_dir(self.tool_dir):
                logger.warning('Directory "{dir}" does not exist'.format(
                    dir=self.tool_dir))
                #return False
            elif not FileUtils.remove_directory(self.tool_dir):
                logger.error('Unable to delete directory "{dir}". ' \
                    'Check permissions and/or re-run with sudo'.format(
                        dir=self.tool_dir))  
                return False
            else:
                logger.success('Tool directory "{dir}" deleted'.format(
                    dir=self.tool_dir))

        # Make sure "installed" option in config file is set to False
        if settings.change_installed_status(self.target_service, 
                                            self.name, 
                                            install_status=False):
            logger.success('Tool marked as uninstalled')
        else:
            logger.error('An unexpected error occured when trying to mark the tool ' \
                'as uninstalled !')
            return False

        self.installed = False
        return True


    #------------------------------------------------------------------------------------
    # Preparation of an Installation

    def __create_tool_dir(self):
        """
        Create the tool directory if necessary.

        :return: Status
        :rtype: bool
        """
        if self.tool_dir:
            if FileUtils.is_dir(self.tool_dir):
                logger.info('Directory "{dir}" already exists'.format(dir=self.tool_dir))
                return True

            try:
                FileUtils.create_directory(self.tool_dir)
            except Exception as e:
                logger.error('Unable to create new directory "{dir}": {exc}'.format(
                    dir=self.tool_dir, exc=e))
                return False
            logger.info('New directory "{dir}" created'.format(dir=self.tool_dir))
            return True
        else:
            return False


    def __check_pre_install(self, settings, fast_mode=False):
        """
        Perform some checks before trying to install the tool (already installed ?,
        install command ?).

        :param Settings settings: Settings from config files
        :param bool fast_mode: Set to true to disable prompts
        :return: Result of checks
        :rtype: bool
        """
        if self.installed:
            logger.info('{tool} is already installed (according to settings), ' \
                'skipped'.format(tool=self.name))
            return False

        elif not self.install_command:
            logger.warning('The tool {tool} has no installation command specified in ' \
                'config file'.format(tool=self.name))

            if fast_mode \
               or Output.prompt_confirm('Is the tool already installed on your system ?',
                                        default=True):

                try:
                    if settings.change_installed_status(self.target_service, 
                                                        self.name, 
                                                        True):

                        logger.success('Tool {tool} has been marked as installed in ' \
                            'settings'.format(tool=self.name))
                        return True
                    else:
                        logger.error('Error when saving the configuration file ' \
                            '"{filename}{ext}"'.format(
                                filename=INSTALL_STATUS_CONF_FILE, ext=CONF_EXT))
                        return False

                except SettingsException as e:
                    logger.error(e)
                    self.remove(settings)
                    return False
            else:
                logger.info('Tool {tool} is still not marked as installed in ' \
                    'settings'.format(tool=self.name))
            return False

        return True


    #------------------------------------------------------------------------------------
    # Preparation of an Update

    def __check_pre_update(self, settings, fast_mode=False):
        """
        Perform some checks before trying to update the tool (already installed ?,
        update command ?).

        :param Settings settings: Settings from config files
        :param bool fast_mode: Set to true to disable prompts
        :return: Result of checks
        :rtype: bool
        """
        if not self.installed:
            logger.info('{tool} is not installed yet (according to settings), ' \
                'skipped'.format(tool=self.name))
            return False

        elif not self.update_command:
            logger.warning('No tool update command specified in config file, skipped.')
            return False

        # Create directory for the tool if necessary 
        # (should not be necessary because only update)
        if self.install_command and not FileUtils.is_dir(self.tool_dir):
            logger.warning('Tool directory does not exist but tool marked as ' \
                'installed. Trying to re-install it...')
            return self.install(settings, fast_mode)

        return True


    #------------------------------------------------------------------------------------
    # Run Install/Update

    def __run_install_update(self, fast_mode, update=False):
        """
        Run install or update command.

        :param fast_mode: Set to true to disable prompts
        :param update: Mode selector, True for update | False for install (default)
        :return: Install/Update status
        :rtype: bool
        """
        if update : cmd = self.update_command.get_cmdline(self.tool_dir)
        else      : cmd = self.install_command.get_cmdline(self.tool_dir)

        mode = 'update' if update else 'install'

        logger.info('Description: {descr}'.format(descr=self.description))
        #Output.print('{mode} command : {cmd}'.format(
        #   mode=mode.capitalize(), cmd=cmd_short))

        if fast_mode \
           or Output.prompt_confirm('Confirm {mode} ?'.format(mode=mode), default=True):

            Output.begin_cmd(cmd)
            returncode, _ = ProcessLauncher(cmd).start()
            Output.delimiter()
            if returncode != 0:
                logger.warning('Tool {mode} has finished with an error ' \
                    'exit code: {code}'.format(mode=mode, code=returncode))
            else:
                logger.success('Tool {mode} has finished with success exit code'.format(
                    mode=mode))
            return True
        else:
            logger.warning('Tool {mode} aborted'.format(mode=mode))
            return False


    #------------------------------------------------------------------------------------
    # Post-install/update Check

    def __check_post_install_update(self, settings, fast_mode=False, update=False):
        """
        Perform some operation after install/update:
            - Check if correctly installed by running "check_command" and prompting,
            - Update install status in configuration file.

        :param Settings settings: Settings from config files
        :param bool fast_mode: Set to true to disable prompts
        :param update: Mode selector, True for update | False for install (default)
        :return: Status of operations
        :rtype: bool
        """
        mode = ('update','updated') if update else ('install','installed')
        status = True

        # Check install/update
        if not self.check_command:
            logger.info('No check_command defined in settings for {tool}, will ' \
                'assume it is correctly {mode}'.format(tool=self.name, mode=mode[1]))
        else:
            logger.info('Now, checking if {tool} has been {mode} correctly.' \
                '{key}'.format(
                    tool=self.name, 
                    mode=mode[1], 
                    key='Hit any key to run test...' if not fast_mode else ''))
            if not fast_mode:
                CLIUtils.getch()
            status = self.run_check_command(fast_mode)

        # Change install status in configuration file
        if status:
            try:

                if settings.change_installed_status(self.target_service, 
                                                    self.name, 
                                                    install_status=True):

                    logger.success('Tool {tool} has been marked as successfully ' \
                        '{mode}'.format(tool=self.name, mode=mode[1]))
                    return True
                else:
                    logger.error('Error when updating configuration file ' \
                        '"{filename}{ext}"'.format(
                            filename=INSTALL_STATUS_CONF_FILE, ext=CONF_EXT))
                    return False

            except SettingsException as e:
                logger.error('An unexpected error occured when trying to mark the '\
                    'tool as {mode}: {exc}'.format(mode=mode[1], exc=e))

                if not update:
                    self.remove(settings)
                return False
        else:
            logger.warning('Tool {tool} has not been marked as {mode}'.format(
                tool=self.name, mode=mode[1]))
            if not update:
                self.remove(settings)
            else:
                if not fast_mode \
                   and Output.prompt_confirm('Do you want to try to re-install ?', 
                                             default=True):

                    return self.__reinstall(settings, fast_mode)

            return False


    def run_check_command(self, fast_mode=False):
        """
        Run the check command.
        The goal is to quickly check if the tool is not buggy or missing some 
        dependencies. The user must analyze the output and gives an answer.

        :param bool fast_mode: Set to true to disable prompts

        :return: Response from user in interactive mode, otherwise status
            based on exit code (True if exit code is 0)
        :rtype: bool
        """
        if not self.check_command:
            logger.info('No check_command defined in settings for the tool ' \
                '{tool}'.format(tool=self.name))
            return True

        logger.info('Running the check command for the tool {tool}...'.format(
            tool=self.name))

        cmd = self.check_command.get_cmdline(self.tool_dir)

        Output.begin_cmd(cmd)
        returncode, _ = ProcessLauncher(cmd).start()
        Output.delimiter()

        if returncode != 0:
            logger.warning('Check command has finished with an error ' \
                'exit code: {code}'.format(code=returncode))
        else:
            logger.success('Check command has finished with success exit code')

        if fast_mode:
            return (returncode == 0)
        else:
            return Output.prompt_confirm('Does the tool {tool} seem to be running ' \
                'correctly ?'.format(tool=self.name), default=True) 


    #------------------------------------------------------------------------------------

    def __reinstall(self, settings, fast_mode):
        """
        Try to re-install the tool, i.e. remove and install.

        :param Settings settings: Settings from config files
        :param fast_mode: Set to true to disable prompts
        :return: Status of reinstall
        :rtype: bool
        """
        logger.info('First, the tool directory will be removed...')
        if not self.remove(settings):
            return False
        logger.info('Now, running a new install for {tool}...'.format(tool=self.name))
        return self.install(settings)



