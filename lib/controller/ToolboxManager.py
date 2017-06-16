###
### Controller > ToolboxManager
###

import sys
from lib.output import *
from lib.core.SpecificOptions import SpecificOptions
from lib.utils.FileUtils import FileUtils
from lib.utils.CLIUtils import CLIUtils


class ToolboxManager(object):

	def __init__(self, arguments, settings, output):
		self.settings     = settings
		self.arguments    = arguments
		self.output       = output


	def run(self):
		if self.arguments.args.show_toolbox:
			service = self.arguments.args.show_toolbox
			#self.output.printInfo('Selected mode: Show toolbox content for service {0}'.format(service))
			self.settings.toolbox.printToolboxForService(self.output, service)
			sys.exit(0)

		if self.arguments.args.show_toolbox_brief:
			service = self.arguments.args.show_toolbox_brief
			#self.output.printInfo('Selected mode: Show toolbox content (brief) for service {0}'.format(service))
			print
			self.settings.toolbox.printToolboxBriefForService(self.output, service)
			sys.exit(0)

		if self.arguments.args.install_toolbox:
			service = self.arguments.args.install_toolbox
			#self.output.printInfo('Selected mode: Toolbox install for service {0}'.format(service))
			print
			self.settings.toolbox.installToolboxForService(self.output, service, fast_mode=self.arguments.args.fast_install)
			sys.exit(0)

		if self.arguments.args.install_all:
			self.output.printInfo('Selected mode: Toolbox install for all services')
			print
			self.settings.toolbox.installToolbox(self.output, fast_mode=self.arguments.args.fast_install)
			sys.exit(0)

		if self.arguments.args.update_toolbox:
			service = self.arguments.args.update_toolbox
			self.output.printInfo('Selected mode: Toolbox update for service {0}'.format(service))
			print
			self.settings.toolbox.updateToolboxForService(self.output, service, fast_mode=self.arguments.args.fast_install)
			sys.exit(0)

		if self.arguments.args.update_all:
			self.output.printInfo('Selected mode: Toolbox update for all services')
			print
			self.settings.toolbox.updateToolbox(self.output, fast_mode=self.arguments.args.fast_install)
			sys.exit(0)

		if self.arguments.args.uninstall_tool:
			tool_name = self.arguments.args.uninstall_tool
			self.output.printInfo('Selected mode: Uninstall tool named "{0}"'.format(tool_name))
			print
			self.settings.toolbox.removeTool(self.output, tool_name)
			sys.exit(0)

		if self.arguments.args.uninstall_toolbox:
			service = self.arguments.args.uninstall_toolbox
			self.output.printInfo('Selected mode: Uninstall toolbox for service {0}'.format(service))
			print
			self.settings.toolbox.removeToolboxForService(self.output, service)
			sys.exit(0)

		if self.arguments.args.uninstall_all:
			#self.output.printInfo('Selected mode: Uninstall the whole toolbox')
			print
			self.settings.toolbox.removeToolbox(self.output)
			sys.exit(0)

		if self.arguments.args.list_services:
			#self.output.printInfo('Selected mode: List supported services')
			print
			self.settings.toolbox.printListSupportedServices(self.output)
			sys.exit(0)

		if self.arguments.args.list_categories:
			service = self.arguments.args.list_categories
			#self.output.printInfo('Selected mode: List tools categories for service {0}'.format(service))
			print
			self.settings.toolbox.printListCategories(self.output, service)
			sys.exit(0)

		if self.arguments.args.list_specific:
			service = self.arguments.args.list_specific
			self.output.printInfo('Selected mode: List context specific options for service {0}'.format(service))
			print
			SpecificOptions.listAvailableSpecificOptions(self.settings, service, self.output)
			sys.exit(0)



