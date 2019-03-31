#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Check
###
import sys
from collections import OrderedDict

from lib.core.Config import *
from lib.core.ProcessLauncher import ProcessLauncher
from lib.db.CommandOutput import CommandOutput
from lib.db.Result import Result
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.requester.ResultsRequester import ResultsRequester
from lib.utils.StringUtils import StringUtils
from lib.smartmodules.SmartPostcheck import SmartPostcheck


class Check:
    """Security check"""

    def __init__(self, name, category, description, tool, commands):
        """
        Construct Check object.

        :param str name: Name of the check
        :param str category: Category of the check
        :param str description: Description of the check
        :param Tool tool: Tool which is used by the check
        :param list(Command) commands: Commands for the check
        """
        self.name        = name
        self.category    = category
        self.description = description
        self.tool        = tool
        self.commands    = commands


    #------------------------------------------------------------------------------------

    def check_target_compliance(self, target):
        """
        Check if target complies with any of the context requirements of the different 
        commands defined in the security check.

        :param Target target: Target
        :return: Check result
        :rtype: bool
        """
        i = 1
        for command in self.commands:
            logger.debug('{check} - Command #{i} context requirements: {rawstr}'.format(
                check=self.name, i=i, rawstr=command.context_requirements))
            i += 1
            if command.context_requirements.check_target_compliance(target):
                return True
        return False


    #------------------------------------------------------------------------------------

    def run(self, 
            target, 
            arguments, 
            sqlsession,
            fast_mode=False):
        """
        Run the security check.
        It consists in running commands with context requirements matching with the
        target's context.

        :param Target target: Target
        :param ArgumentsParser arguments: Arguments from command-line
        :param Session sqlsession: SQLAlchemy session
        :param SmartModulesLoader smartmodules_loader: Loader of SmartModules
        :param bool fast_mode: Set to true to disable prompts
        :return: Status
        :rtype: bool
        """
        if not self.tool.installed:
            return False

        i = 1
        command_outputs = list()
        for command in self.commands:
            if command.context_requirements.check_target_compliance(target):
                if not command.context_requirements.is_empty:
                    logger.info('Command #{num:02} matches requirements: ' \
                        '{context}'.format(num=i, context=command.context_requirements))

                cmdline = command.get_cmdline(self.tool.tool_dir, target, arguments)

                if fast_mode:
                    logger.info('Run command #{num:02}'.format(num=i))
                    mode = 'y'
                else:
                    mode = Output.prompt_choice(
                        'Run command {num}? [Y/n/f/q] '.format(
                            num='' if len(self.commands) == 1 else \
                                '#{num:02} '.format(num=i)), 
                        choices={
                            'y': 'Yes',
                            'n': 'No',
                            #'t': 'New tab',
                            #'w': 'New window',
                            'f': 'Switch to fast mode (do not prompt anymore)',
                            'q': 'Quit the program',
                        },
                        default='y')

                if mode == 'q':
                    logger.warning('Exit !')
                    sys.exit(0)
                elif mode == 'n':
                    logger.info('Skipping this command')
                    continue
                else:
                    if mode == 'f':
                        logger.info('Switch to fast mode')
                        arguments.args.fast_mode = True

                    Output.begin_cmd(cmdline)
                    process = ProcessLauncher(cmdline)
                    if mode == 'y' or mode == 'f':
                        output = process.start()
                    # elif mode == 't':
                    #     output = process.start_in_new_tab()
                    #     logger.info('Command started in new tab')
                    # else:
                    #     output = process.start_in_new_window(self.name)
                    #     logger.info('Command started in new window')
                    Output.delimiter()
                    print()

                    outputraw = StringUtils.remove_ansi_escape(output)
                    command_outputs.append(CommandOutput(
                        cmdline=cmdline, 
                        output=output, 
                        outputraw=outputraw))

                    # Run smartmodule method on output
                    postcheck = SmartPostcheck(
                        target.service,
                        sqlsession,
                        self.tool.name,
                        '{0}\n{1}'.format(cmdline, outputraw))
                    postcheck.run()


            else:
                logger.info('Command #{num:02} does not match requirements: ' \
                    '{context}'.format(num=i, context=command.context_requirements))
                logger.debug('Context string: {rawstr}'.format(
                    rawstr=command.context_requirements))
            
            i += 1

        # Add outputs in database
        if command_outputs:
            results_requester = ResultsRequester(sqlsession)
            results_requester.add_result(target.service.id, 
                                         self.name, 
                                         self.category, 
                                         command_outputs)

        return True



        