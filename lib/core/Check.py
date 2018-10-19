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


class Check:

    def __init__(self, 
                 name,
                 category,
                 description,
                 tool,
                 commands,
                 postrun):
        """
        :param name: Name of the check (mandatory)
        :param category: Category of the check (mandatory)
        :param description: Description of the check (mandatory)
        :param tool: Tool instance to use (mandatory)
        :param commands: List of Command instances, each one may have an associated Context (mandatory, at least one)
        :param postrun: Method from smartmodules to run after the command (optional)
        """
        self.name        = name
        self.category    = category
        self.description = description
        self.tool        = tool
        self.commands    = commands
        self.postrun     = postrun


    def is_matching_context(self, target):
        for command in self.commands:
            if target.is_matching_context(command.context):
                return True
        return False


    def run(self, target, smartmodules_loader, results_requester, fast_mode=False):
        """
        Run the check, i.e. run the commands for which Target's specific options and authentication
        level are matching the required context.
        :param target  : Target object
        :param smartmodules_loader: 
        :param results_requester: ResultsRequester object
        :param fast_mode: Boolean indicating whether prompts must be displayed or not
        :return:
        """
        if not self.tool.installed:
            return False

        i = 1
        command_outputs = list()
        for command in self.commands:
            if target.is_matching_context(command.context):
                if command.context:
                    logger.info('Command #{num:02} is matching current target\'s context: {context}'.format(
                        num=i, context=command.context))

                cmdline = command.get_cmdline(self.tool.tool_dir, target)

                #if i == 1:  logger.info('Check: {descr}'.format(descr=self.description))
                #logger.info('Command #{num:02}: {cmd}'.format(num=i, cmd=cmd_short))
                if fast_mode:
                    logger.info('Run command #{num:02}'.format(num=i))
                    mode = 'y'
                else:
                    mode = Output.prompt_choice('Run command #{num:02} ? [Y/n/t/w/q] '.format(num=i), 
                        choices={
                            'y':'Yes',
                            'n':'No',
                            't':'New tab',
                            'w':'New window',
                            'q':'Quit the program'
                        },
                        default='y')

                if mode == 'q':
                    logger.warning('Exit !')
                    sys.exit(0)
                elif mode == 'n':
                    logger.info('Skipping this command')
                    continue
                else:
                    Output.begin_cmd(cmdline)
                    process = ProcessLauncher(cmdline)
                    if mode == 'y':
                        output = process.start()
                    elif mode == 't':
                        output = process.start_in_new_tab()
                        logger.info('Command started in new tab')
                    else:
                        output = process.start_in_new_window(self.name)
                        logger.info('Command started in new window')
                    Output.delimiter()
                    print()

                    command_outputs.append(CommandOutput(cmdline=cmdline, output=output))

                    if self.postrun:
                        smartmodules_loader.call_postcheck_method(self.postrun, target.service, output)

            else:
                logger.info('Command #{num:02} is not matching current target\'s context: {context}'.format(
                    num=i, context=command.context))
            
            i += 1

        if i == 1:
            logger.warning('This check is skipped')
        else: 
            # Add output(s) in db
            results_requester.add_result(target.service.id, self.name, self.category, command_outputs)



        