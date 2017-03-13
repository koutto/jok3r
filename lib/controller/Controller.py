###
### Controller
###

import sys
import time
from lib.output import *
from lib.core.SpecificOptions import SpecificOptions
from lib.utils.FileUtils import FileUtils
from lib.utils.CLIUtils import CLIUtils


class Controller(object):

    def __init__(self, script_path, arguments, settings, output):
        self.script_path  = script_path
        self.settings     = settings
        self.arguments    = arguments
        self.output       = output

		# Toolbox management
        print
        if self.arguments.args.show_toolbox:
            service = self.arguments.args.show_toolbox
            self.output.printInfo('Selected mode: Show toolbox content for service {0}'.format(service))
            self.settings.toolbox.printToolboxForService(self.output, service)
            sys.exit(0)

        if self.arguments.args.show_toolbox_brief:
            service = self.arguments.args.show_toolbox_brief
            self.output.printInfo('Selected mode: Show toolbox content (brief) for service {0}'.format(service))
            self.settings.toolbox.printToolboxBriefForService(self.output, service)
            sys.exit(0)

        if self.arguments.args.install_toolbox:
            service = self.arguments.args.install_toolbox
            self.output.printInfo('Selected mode: Toolbox install for service {0}'.format(service))
            self.settings.toolbox.installToolboxForService(self.output, service)
            sys.exit(0)

        if self.arguments.args.install_all:
            self.output.printInfo('Selected mode: Toolbox install for all services')
            self.settings.toolbox.installToolbox(self.output)
            sys.exit(0)

        if self.arguments.args.update_toolbox:
            service = self.arguments.args.update_toolbox
            self.output.printInfo('Selected mode: Toolbox update for service {0}'.format(service))
            self.settings.toolbox.updateToolboxForService(self.output, service)
            sys.exit(0)

        if self.arguments.args.update_all:
            self.output.printInfo('Selected mode: Toolbox update for all services')
            self.settings.toolbox.updateToolbox(self.output)
            sys.exit(0)

        if self.arguments.args.uninstall_tool:
            tool_name = self.arguments.args.uninstall_tool
            self.output.printInfo('Selected mode: Uninstall tool named "{0}"'.format(tool_name))
            self.settings.toolbox.removeTool(self.output, tool_name)
            sys.exit(0)

        if self.arguments.args.uninstall_toolbox:
            service = self.arguments.args.uninstall_toolbox
            self.output.printInfo('Selected mode: Uninstall toolbox for service {0}'.format(service))
            self.settings.toolbox.removeToolboxForService(self.output, service)
            sys.exit(0)

        if self.arguments.args.uninstall_all:
            self.output.printInfo('Selected mode: Uninstall the whole toolbox')
            self.settings.toolbox.removeToolbox(self.output)
            sys.exit(0)

        if self.arguments.args.list_services:
            self.output.printInfo('Selected mode: List supported services')
            self.settings.toolbox.printListSupportedServices(self.output)
            sys.exit(0)

        if self.arguments.args.list_categories:
            service = self.arguments.args.list_categories
            self.output.printInfo('Selected mode: List tools categories for service {0}'.format(service))
            self.settings.toolbox.printListCategories(self.output, service)
            sys.exit(0)

        if self.arguments.args.list_specific:
            service = self.arguments.args.list_specific
            self.output.printInfo('Selected mode: List context specific options for service {0}'.format(service))
            SpecificOptions.listAvailableSpecificOptions(self.settings, service, self.output)
            sys.exit(0)


        service = self.arguments.args.service
        output.printInfo('Selected mode: Run tools againt target - Service {0}'.format(service))
        print

        # Print target info
        output.printTitle0('Target Summary:')
        self.arguments.target.printSummary(output)

        begin = time.time()

        # Single tool mode
        if self.arguments.args.single_tool:
            tool = self.settings.toolbox.isInToolboxForService(self.arguments.args.single_tool, service)
            if not tool:
                sys.exit(0)

            subdir = FileUtils.concat_path(self.arguments.args.output_dir, tool.category)
            output_file = FileUtils.absolute_path(FileUtils.concat_path(subdir, tool.name + '.txt'))
            output_dir  = FileUtils.absolute_path(FileUtils.concat_path(subdir, tool.name))
            print
            output.printTitle1('   ' + tool.name)
            try:
                tool.runTool(self.settings, 
                             output, 
                             output_file, 
                             output_dir, 
                             self.arguments.target, 
                             self.arguments.specific,
                             False,
                             False)
            except KeyboardInterrupt, SystemExit:
                print
                self.output.printError('Tool execution aborted')
                
            print    

        # Normal mode
        else:    
            # Print config
            output.printTitle0('Configuration:')
            self.arguments.printSummary(output)

            # Processing
            for cat in self.arguments.selected_tools_categories:
                print
                output.printTitle0('Tools Category - {0}'.format(cat))
                if not self.settings.toolbox.tools[service][cat]:
                    output.printInfo('No tool to run in this category')
                    continue

                if not self.arguments.args.auto_yes:
                    output.printPrompt('Run tools in this category ? [Y/n]')
                    # Prompt
                    to_run = CLIUtils.promptYesNo(output, default='Y')
                    if not to_run:
                        output.printWarning('Category skipped.')
                        continue

                subdir = FileUtils.concat_path(self.arguments.args.output_dir, cat)
                if not FileUtils.create_directory(subdir):
                    output.printFail('Impossible to create output subdir "{0}"'.format(subdir))
                    sys.exit(0)
                output.printInfo('Output subdir "{0}" created'.format(subdir))
                for tool in self.settings.toolbox.tools[service][cat]:
                    print
                    output.printTitle1('   ' + tool.name)

                    # Output for each tool is stored into a file
                    output_file = FileUtils.absolute_path(FileUtils.concat_path(subdir, tool.name + '.txt'))
                    # Some tools (e.g. skipfish) required an output dir too
                    output_dir  = FileUtils.absolute_path(FileUtils.concat_path(subdir, tool.name))
                    try:
                        tool.runTool(self.settings, 
                                     output, 
                                     output_file, 
                                     output_dir, 
                                     self.arguments.target, 
                                     self.arguments.specific,
                                     self.arguments.args.ignore_specific,
                                     self.arguments.args.auto_yes)
                    except KeyboardInterrupt, SystemExit:
                        print
                        self.output.printError('Tool execution aborted')
                        
                    print
        print
        self.output.printInfo('Processing terminated - time spent: {0} seconds'.format(int(time.time()-begin)))
