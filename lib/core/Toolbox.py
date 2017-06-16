###
### Core > Toolbox
###

import os
from collections import OrderedDict
from lib.utils.FileUtils import FileUtils
from lib.core.Constants import *

class Toolbox(object):

	def __init__(self, settings):
		self.settings	= settings
		# self.tools: 2 dimensions dict - [service_name][tools_categories]
		self.tools 		= OrderedDict()

	def __getitem__(self, key):
		return self.tools[key]

	def __setitem__(self, key, item):
		self.tools[key] = item
		

	def addService(self, service_name):
		"""
		Add a service as new section in toolbox

		@Args		service_name: Name of the service to add
		"""
		self.tools[service_name] = OrderedDict()
		for cat in self.settings.general_settings[service_name]['tools_categories']:
			self.tools[service_name][cat] = []


	def addTool(self, tool, service_name):
		"""
		Add a tool (object) into the toolbox

		@Args		tool: 			The tool to Add (instance of Tool class)
					service_name: 	Name of the service section (must exist into the toolbox)
		@Returns 	Boolean indicating operation status
		"""
		if service_name not in self.tools.keys() or tool in self.tools[service_name][tool.category]:
			return False
		self.tools[service_name][tool.category].append(tool)
		return True


	def searchInToolbox(self, tool_name):
		"""
		Search a tool inside the toolbox. Global search accross various services.

		@Args		tool: 	the tool name to search for
		@Returns 	- Success: Tool object
					- Fail: None
		"""
		for service in self.tools.keys():
			for cat in self.tools[service]:
				for t in self.tools[service][cat]:
					if tool_name.lower().strip() == t.name.lower():
						return t
		return None


	def searchInToolboxForService(self, tool_name, service_name):
		"""
		Search a tool targeting a given service inside the toolbox.

		@Args		tool: 			the tool name to check the presence of
					service_name: 	the service name the search should focus on
		@Returns 	- Success: Tool object
					- Fail: None
		"""
		if service_name not in self.tools.keys():
			return None

		for cat in self.tools[service_name]:
			for t in self.tools[service_name][cat]:
				if tool_name.lower().strip() == t.name.lower():
					return t
		return None


	def searchInToolboxToolsReferencing(self, tool_ref_name):
		"""
		"""
		tools = []

		for service in self.tools.keys():
			for cat in self.tools[service]:
				for t in self.tools[service][cat]:
					if tool_ref_name.lower().strip() == t.tool_ref_name.lower():
						tools.append(t)

		return tools


	def printToolboxForService(self, output, service_name):
		"""
		Print summary of the part of the toolbox targeting a given service

		@Args		output: 		Instance of CLIOutput
					service_name:  	Name of the service (must exist into the toolbox)
		"""
		if service_name not in self.tools.keys():
			return

		i = 0
		nb_tools 		= 0
		nb_installed 	= 0
		output.printTitle1('      Toolbox content for service {0}'.format(service_name))
		print
		for c in self.tools[service_name].keys():
			output.printTitle0('0x{0:02X} - {1}'.format(i, c))
			i += 1
			if len(self.tools[service_name][c]) == 0:
				output.printNewLine('     No tool registered in this category yet')
			else:
				for tool in self.tools[service_name][c]:
					nb_tools += 1
					if tool.installed:
						nb_installed += 1
					tool.printToolSummary(output)
					print
			print
		output.printInfo('Total number of tools: {0}'.format(nb_tools))
		output.printInfo('Installed tools      : {0}'.format(nb_installed))
		print


	def printToolboxBriefForService(self, output, service_name):
		"""
		Brief version of printToolboxForService()

		@Args		output: 		Instance of CLIOutput
					service_name:  	Name of the service section (must exist into the toolbox)
		"""		
		if service_name not in self.tools.keys():
			return

		i = 0
		nb_tools 		= 0
		nb_installed 	= 0
		output.printTitle1('      Toolbox content for service {0}'.format(service_name))
		print
		for c in self.tools[service_name].keys():
			output.printTitle1('0x{0:02X} - {1}'.format(i, c))
			i += 1
			if len(self.tools[service_name][c]) == 0:
				output.printNewLine('     No tool registered in this category yet')
			else:
				for tool in self.tools[service_name][c]:
					nb_tools += 1
					if tool.installed:
						nb_installed += 1
					tool.printToolSummaryBrief(output)
			print
		output.printInfo('Total number of tools: {0}'.format(nb_tools))
		output.printInfo('Installed tools      : {0}'.format(nb_installed))
				

	def printListSupportedServices(self, output):
		"""
		Print the list of supported services inside toolbox

		@Args 		output: 	Instance of CLIOutput
		"""
		output.printTitle1('      List of supported services:')
		print
		output.printNewLine('{0:20}Installed tools  Categories'.format(''))
		for service_name in self.tools.keys():
			if service_name == MULTI_SERVICES_CONF_FILE: 
				continue
			nb_tools 	 = sum(len(self.tools[service_name][cat]) for cat in self.tools[service_name].keys())
			nb_cats  	 = len(self.tools[service_name])
			nb_installed = self.nbToolsInstalledForService(service_name)

			output.printNewLine('  - {0:25}[ {1:2} / {2:2} ]      [ {3:2} ]'.format(output.boldString(service_name), \
				nb_installed, nb_tools, nb_cats))
		print


	def printListCategories(self, output, service_name):
		"""
		Print the list of tools categories for a given service

		@Args 		output: 		Instance of CLIOutput
					service_name:	Name of the service section (must exist into the toolbox)
		"""
		if service_name not in self.tools.keys():
			return

		output.printTitle1('      List of tools categories for {0}:'.format(service_name))
		print
		output.printNewLine('{0:30}Installed tools'.format(''))
		for c in self.tools[service_name].keys():
			nb_tools     = len(self.tools[service_name][c])
			nb_installed = sum(1 if tool.installed else 0 for tool in self.tools[service_name][c]) 
			output.printNewLine('  - {0:35} [ {1:2} / {2:2} ]'.format(output.boldString(c), \
				nb_installed, nb_tools))
		print


	def removeTool(self, output, tool_name):
		"""
		Remove a tool from the toolbox

		@Args		output: 		Instance of CLIOutput
					tool_name: 		Name of the tool to remove
					service_name: 	Name of the service section (must exist into the toolbox)
		@Returns 	Boolean indicating operation status
		"""
		tool = self.searchInToolbox(tool_name)
		if tool:
			if tool.removeTool(self.settings, output):
				output.printSuccess('Tool "{0} deleted with success'.format(tool_name))
				return True
			elif tool.tooltype != ToolType.USE_MULTI:
				output.printWarning('Tool "{0}" not deleted'.format(tool_name))
				return False
			else:
				return True
		output.printFail('Tool "{0}" has not been found into toolbox'.format(tool_name))
		return False


	def removeToolbox(self, output):
		"""
		Remove all tools in the toolbox

		@Args 		output: 		Instance of CLIOutput
		"""
		output.printTitle1('      Uninstall everything')
		for service_name in self.tools.keys():
			self.removeToolboxForService(output, service_name)


	def removeToolboxForService(self, output, service_name):
		"""
		Remove all tools for a given service

		@Args 		output: 		Instance of CLIOutput
					service_name:	Name of the service section (must exist into the toolbox)
		@Returns 	Boolean
		"""
		if service_name not in self.tools.keys():
			return False

		no_error = True
		for cat in self.tools[service_name].keys():
			for tool in self.tools[service_name][cat]:
				if tool.removeTool(self.settings, output):
					output.printSuccess('Tool "{0}" deleted with success'.format(tool.name))
				elif tool.tooltype != ToolType.USE_MULTI:
					output.printWarning('Tool "{0}" not deleted'.format(tool.name))
					no_error = False

		if no_error:
			toolbox_service_dir = self.settings.toolbox_dir + os.sep + service_name
			if FileUtils.remove_directory(toolbox_service_dir):
				output.printSuccess('Directory "{0}" deleted with success'.format(toolbox_service_dir))
				return True
			else:
				output.printWarning('Directory "{0}" not empty, cannot delete it. Try to remove it manually')
				return False
		else:
			return False


	def installToolbox(self, output, fast_mode=False):
		"""
		Install tools in the toolbox.
		Interactive prompts are displayed for each tool to confirm install.

		toolbox/
			+-- service1/
				+-- category1/
					+-- tool1/
					+-- tool2/
					...
				+-- category2/
				...
			+-- service2/
			...

		@Args		output: 	Instance of CLIOutput
					fast_mode: 	Boolean indicating if prompt for confirmation must be used
		"""
		for service_name in self.tools.keys():
			self.installToolboxForService(output, service_name, fast_mode=fast_mode)


	def installToolboxForService(self, output, service_name, fast_mode=False):
		"""
		Install tools in the toolbox for a given service

		@Args 		output: 		Instance of CLIOutput
					service_name:	Name of the service section (must exist into the toolbox)
					fast_mode: 		Boolean indicating if prompt for confirmation must be used
		"""
		if service_name not in self.tools.keys():
			return

		output.printTitle1('      Install tools for service: {0}'.format(service_name))
		print
		i = 0
		for cat in self.tools[service_name].keys():
			output.printTitle0('0x{0:02X} - {1}'.format(i, cat))
			i += 1
			if len(self.tools[service_name][cat]) == 0:
				output.printNewLine('No tool registered in this category yet')
			else:
				for tool in self.tools[service_name][cat]:
					output.printTitle1('   {0}'.format(tool.name))
					tool.runInstall(self.settings, output, fast_mode=fast_mode)


	def updateToolbox(self, output, fast_mode=False):
		"""
		Update tools in the toolbox

		@Args		output: 	Instance of CLIOutput
					fast_mode: 	Boolean indicating if prompt for confirmation must be used
		"""
		for service_name in self.tools.keys():
			self.updateToolboxForService(output, service_name, fast_mode=fast_mode)


	def updateToolboxForService(self, output, service_name, fast_mode=False):
		"""
		Update tools in the toolbox for a given service
		@Args 		output: 		Instance of CLIOutput
					service_name:	Name of the service section (must exist into the toolbox)
					fast_mode: 		Boolean indicating if prompt for confirmation must be used
		"""
		if service_name not in self.tools.keys():
			return

		output.printTitle1('      Update toolbox for service: {0}'.format(service_name))
		print
		i = 0
		for cat in self.tools[service_name].keys():
			output.printTitle0('0x{0:02X} - {1}'.format(i, cat))
			i += 1
			if len(self.tools[service_name][cat]) == 0:
				output.printNewLine('No tool registered in this category yet')
			else:
				for tool in self.tools[service_name][cat]:
					output.printTitle1('   {0}'.format(tool.name))
					tool.runUpdate(self.settings, output, fast_mode=fast_mode)
			print
		print

	def nbToolsInstalledForService(self, service_name):
		"""
		Returns the number of tools installed targeting a given service, inside the toolbox
		@Args 		service_name
		@Returns 	int 	The number of installed tools
		"""
		if service_name not in self.tools.keys():
			return 0

		nb = 0
		for cat in self.tools[service_name].keys():
			for tool in self.tools[service_name][cat]:
				if tool.installed:
					nb += 1
		return nb