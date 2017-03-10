###
### Toolbox
###
### - Basically, a toolbox is just a dict of tools, classified by categories
###
### toolbox/
###	http/
###		cat1/
###		cat2/
###
###	ftp/
###
import os
from collections import OrderedDict
from lib.utils.FileUtils import FileUtils

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
		@Args		service_name: name of the service to add
		"""
		self.tools[service_name] = OrderedDict()
		for cat in self.settings.general_settings[service_name]['tools_categories']:
			self.tools[service_name][cat] = []


	def addTool(self, tool, service_name):
		"""
		Add a tool (object) into the toolbox
		@Args		tool: the tool to Add (instance of Tool class)
					service_name: name of the service section (must exist into the toolbox)
		"""
		#try:
		if service_name not in self.tools.keys():
			return False
		if tool in self.tools[service_name][tool.category]:
			return False
		self.tools[service_name][tool.category].append(tool)
		return True
		#except:
		#	# Should never be here
		#	return False


	def isInToolbox(self, tool):
		"""
		Check presence of a tool into the toolbox (global search)
		@Args		tool: 	the tool name to check the presence of
		@Returns 	Tool object if present, otherwise None
		"""
		for service_name in self.settings.general_settings.keys():
			for c in self.settings.general_settings[service_name]['tools_categories']:
				for t in self.tools[service_name][c]:
					if tool.lower().strip() == t.name.lower():
						return t
		return None


	def isInToolboxForService(self, tool, service_name):
		"""
		Check presence of a tool into the toolbox (for a given service)
		@Args		tool: 			the tool name to check the presence of
					service_name: 	the service name the search should focus on
		@Returns 	Tool object if present, otherwise None
		"""
		if service_name not in self.settings.general_settings.keys():
			return

		for c in self.settings.general_settings[service_name]['tools_categories']:
			for t in self.tools[service_name][c]:
				if tool.lower().strip() == t.name.lower():
					return t
		return None


	def printToolboxForService(self, output, service_name):
		"""
		Print summary of toolbox content for targetting a given service
		@Args		output: 		Instance of CLIOutput
					service_name:  	Name of the service section (must exist into the toolbox)
		"""
		if service_name not in self.tools.keys():
			return

		i = 0
		nb_tools 		= 0
		nb_installed 	= 0
		print
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
		Print summary (brief) of toolbox content for targetting a given service
		@Args		output: 		Instance of CLIOutput
					service_name:  	Name of the service section (must exist into the toolbox)
		"""		
		if service_name not in self.tools.keys():
			return

		i = 0
		nb_tools 		= 0
		nb_installed 	= 0
		print
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
		Print the list of supported services
		@Args 		output: 	Instance of CLIOutput
		@Returns 	None
		"""
		print
		output.printTitle1('      List of supported services:')
		print
		for service_name in self.tools.keys():
			output.printNewLine('  - {0} ({1} tools in {2} categories)'.format(output.boldString(service_name), \
				sum(len(self.tools[service_name][cat]) for cat in self.tools[service_name].keys()), len(self.tools[service_name])))
		print


	def printListCategories(self, output, service_name):
		"""
		Print the list of tools categories for a given service
		@Args 		output: 		Instance of CLIOutput
					service_name:	Name of the service section (must exist into the toolbox)
		@Returns 	None
		"""
		if service_name not in self.tools.keys():
			return

		print
		output.printTitle1('      List of tools categories for {0}:'.format(service_name))
		print
		for c in self.tools[service_name].keys():
			output.printNewLine('  - {0} ({1} tools)'.format(output.boldString(c), len(self.tools[service_name][c])))
		print


	def removeTool(self, output, toolname):
		"""
		Remove a tool from the toolbox
		@Args		output: Instance of CLIOutput
					toolname: Name of the tool to remove
					service_name: name of the service section (must exist into the toolbox)
		@Returns 	Boolean
		"""
		for service_name in self.settings.general_settings.keys():
			for c in self.settings.general_settings[service_name]['tools_categories']:
				for t in self.tools[service_name][c]:
					if toolname.lower().strip() == t.name.lower():
						if t.removeTool(self.settings, output):
							output.printSuccess('Tool "{0}"" deleted with success'.format(t.name))
							return True
						else:
							output.printFail('Error during removal of tool "{0}"'.format(t.name))
							return False
		output.printFail('Tool "{0}" has not been found into toolbox'.format(toolname))
		return False


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
		for c in self.settings.general_settings[service_name]['tools_categories']:
			for t in self.tools[service_name][c]:
				if t.removeTool(self.settings, output):
					output.printSuccess('Tool "{0}"" deleted with success'.format(t.name))
				else:
					no_error = False
					output.printFail('Error during removal of tool "{0}"'.format(t.name))

		if no_error:
			toolbox_service_dir = self.settings.toolbox_dir + os.sep + service_name
			if FileUtils.remove_directory(toolbox_service_dir):
				output.printSuccess('Directory "{0}" deleted with success'.format(toolbox_service_dir))
				return True
			else:
				output.printFail('Directory "{0}" not empty, cannot delete it')
				return False
		else:
			return False




	def installToolbox(self, output):
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

		@Args		output: Instance of CLIOutput
		"""
		print
		for service_name in self.tools.keys():
			self.installToolboxForService(output, service_name)


	def installToolboxForService(self, output, service_name):
		if service_name not in self.tools.keys():
			return

		print
		output.printTitle1('      Install tools for service: {0}'.format(service_name))
		print
		i = 0
		for c in self.tools[service_name].keys():
			output.printTitle0('0x{0:02X} - {1}'.format(i, c))
			i += 1
			if len(self.tools[service_name][c]) == 0:
				output.printNewLine('No tool registered in this category yet')
			else:
				for tool in self.tools[service_name][c]:
					output.printTitle1('   ' + tool.name)
					tool.runInstall(self.settings, output)
			print
		print


	def updateToolbox(self, output):
		"""
		Update tools in the toolbox		
		@Args		output: Instance of CLIOutput
		"""
		print
		for service_name in self.tools.keys():
			self.updateToolboxForService(output, service_name)


	def updateToolboxForService(self, output, service_name):
		if service_name not in self.tools.keys():
			return

		print
		output.printTitle1('      Update toolbox for service: {0}'.format(service_name))
		print
		i = 0
		for c in self.tools[service_name].keys():
			output.printTitle0('0x{0:02X} - {1}'.format(i, c))
			i += 1
			if len(self.tools[service_name][c]) == 0:
				output.printNewLine('No tool registered in this category yet')
			else:
				for tool in self.tools[service_name][c]:
					output.printTitle1('   ' + tool.name)
					tool.runUpdate(self.settings, output)
			print
		print