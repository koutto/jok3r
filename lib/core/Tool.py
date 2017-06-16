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
from lib.core.Command import Command, CommandType
import Constants


class ToolType(object):
	STANDARD 		= 1
	MULTI_SERVICES	= 2
	USE_MULTI		= 3


class Tool(object):

	def __init__(self, 
				 service_name,
				 toolbox_dir,
				 tooltype,
				 # General tool options
				 name,
				 tool_ref_name,
				 category,
				 description,
				 command,
				 install,
				 update,
				 installed,
				 last_update,
				 # Specific tool options
				 specific_options):
		"""
		Initialize a Tool object

		@Args		service_name:		service targeted by the tool
					toolbox_dir:		toolbox directory
					tooltype: 			ToolType
					name:				tool name as it will appear in the program
					category:			tool category, must be one of the categories in "tools_categories" general setting
					description: 		tool description, it will be diplayed to user before running tool
					raw_command:		command-line used to launched the tool (can use tags)
					install:			command-line for tool install
					update:				command-line for tool update
					installed:			boolean indicating whether tool is installed or not
					last_update:		date of last tool update		
					specific_options:	dictionary of specific tool options
		"""

		self.service_name	 	= service_name
		self.toolbox_dir	 	= toolbox_dir
		self.tooltype 			= tooltype
		self.name 			 	= name
		self.tool_ref_name		= tool_ref_name
		self.category 		 	= category
		self.description 	 	= description
		self.last_update 	 	= last_update
		self.installed 		 	= installed if isinstance(installed, bool) else False
		self.specific_options 	= specific_options		

		# Directory reserved for the tool
		if self.tooltype == ToolType.USE_MULTI:
			self.tool_dir 	= self.toolbox_dir + os.sep + Constants.MULTI_SERVICES_TOOLBOX_SUBDIR + os.sep + 'all' + os.sep + self.tool_ref_name
		else:
			self.tool_dir 	= self.toolbox_dir + os.sep + self.service_name + os.sep + self.category + os.sep + self.name

		# Commands instantiation
		self.command 	= Command(CommandType.RUN, 		command, 	self.tool_dir, self.toolbox_dir) if command else None
		self.install 	= Command(CommandType.INSTALL, 	install, 	self.tool_dir, self.toolbox_dir) if install else None
		self.update 	= Command(CommandType.UPDATE, 	update, 	self.tool_dir, self.toolbox_dir) if update  else None


	def printToolSummary(self, output):
		"""
		Print tool info nicely

		@Args		output:	CLIOutput instance
		"""

		output.printTitle1('   {0} {1}'.format(self.name, '[-> {0}]'.format(self.tool_ref_name) if self.tool_ref_name else ''))
		output.printNewLine('     Description : {0}'.format(self.description))
		#if self.command: 		output.printNewLine('     Command     : {0}'.format(self.command.cmdline))
		output.printRaw('     Installed   : ')   
		last_update = self.last_update if self.last_update else 'Unknown'
		output.printGreen('Yes [last update: {0}]\n'.format(last_update)) if self.installed else output.printRed('No\n')
		if self.installed: 	output.printNewLine('     Location    : {0}'.format(self.tool_dir))
		if self.specific_options:
			specific = ''
			for option in self.specific_options:
				type_opt  = self.specific_options[option][0]
				value_opt = self.specific_options[option][1]
				if type_opt == bool and value_opt == True:
					specific += '         - {0}: {1}\n'.format(option, 'True')
				elif type_opt == list and value_opt:
					specific += '         - {0}: {1}\n'.format(option, ', '.join(value_opt))
			if specific:
				output.printRaw('     Specific    :\n{0}'.format(specific))


	def printToolSummaryBrief(self, output):
		"""
		Print tool name + install status on one line

		@Args 		output: CLIOutput instance
		"""
		txt = '   - {0}{1}\n'.format(self.name, ' [-> {0}]'.format(self.tool_ref_name) if self.tool_ref_name else '')
		output.printGreen(txt) if self.installed else output.printRed(txt)


	def createToolDirectory(self, output):
		"""
		Create the tool directory if necessary

		@Args		output: 	CLIOutput instance
		@Returns	Boolean indicating operation status
		"""
		if FileUtils.is_dir(self.tool_dir):
			output.printInfo('Directory "{0}" already exists'.format(self.tool_dir))
			return True

		try:
			FileUtils.create_directory(self.tool_dir)
		except Exception as e:
			output.printError('Unable to create new directory "{0}": {1}'.format(self.tool_dir, e))
			return False
		output.printInfo('New directory "{0}" created'.format(self.tool_dir))
		return True


	def runInstall(self, settings, output, fast_mode=False, referencing_tool=None):
		"""
		Install the tool

		@Args		settings: 	Settings instance
					output: 	CLIOutput instance
					fast_mode:	Boolean. If True, do not prompt confirm before install and do not check install after
		@Returns	Boolean indicating status
		"""

		# Check for cases where no install will be run
		if self.installed:
			if self.tooltype == ToolType.USE_MULTI:
				output.printInfo('This is a reference to the tool "{0}" which is already installed, skipped.'.format(self.tool_ref_name))
			else:
				output.printInfo('{0} is already installed (according to config), skipped.'.format(self.name))
			print
			return False

		elif self.tooltype == ToolType.USE_MULTI:
			output.printInfo('This is a reference to the tool "{0}", which is not specific to the service {1}'.format(self.tool_ref_name, self.service_name))
			ref_tool = settings.toolbox.searchInToolboxForService(self.tool_ref_name, Constants.MULTI_SERVICES_CONF_FILE)
			if ref_tool:
				return ref_tool.runInstall(settings, output, fast_mode=fast_mode, referencing_tool=self)
			else:
				output.printFail('The tool "{0}" has not been found inside the conf file "{1}{2}"'.format(self.tool_ref_name, \
					Constants.MULTI_SERVICES_CONF_FILE, Constants.CONF_EXT))
				return False

		elif not self.install:
			output.printWarning('No tool install command specified in config file, skipped')
			if not fast_mode: output.printPrompt('Do you want to mark this tool as installed ? [Y/n]')
			if fast_mode or CLIUtils.promptYesNo(output, default='Y'):
				try:
					if settings.changeInstalledOption(self.service_name, self.name, True):
						output.printSuccess('Tool {0} has been marked as installed. '.format(self.name))
					else:
						output.printError('Error when saving "{0}{1}" configuration file'.format(Constants.INSTALL_STATUS_CONF_FILE, Constants.CONF_EXT))
				except Exception as e:
					output.printError('An unexpected error occured when trying to mark the tool as installed: {0}'.format(e))
					self.removeTool(settings, output)
			else:
				output.printInfo('Tool is still not marked as installed')
			print
			return False

		# Create directory for the tool if necessary
		if not self.createToolDirectory(output):
			output.printFail('Tool install skipped.')
			print
			return False

		# Print basic info and prompt confirmation
		cmd, cmd_short = self.install.getParsedCmdline()
		output.printInfo('Description     : {0}'.format(self.description))
		output.printInfo('Install command : {0}'.format(cmd_short))
		if not fast_mode: output.printPrompt('Install ? [Y/n]')

		# Run install command if wanted
		if fast_mode or CLIUtils.promptYesNo(output, default='Y'):
			output.printBeginCmd(cmd_short)
			process = ProcessLauncher(cmd, output, None)
			process.start()
			output.printEndCmd()
			output.printSuccess('Tool installation has finished')

			# Check install ?
			install_ok = True
			if not (self.tooltype == ToolType.MULTI_SERVICES and not referencing_tool) and not fast_mode:
				output.printInfo('Now, checking if {0} has been installed correctly. Hit any key to run test...'.format(self.name))
				CLIUtils.getch()
				try:
					install_ok = self.checkInstall(output, referencing_tool=referencing_tool)
				except Exception as e:
					install_ok = False
					output.printError('An unexpected error occured when checking install: {0}'.format(e))

			# Change install status in configuration file
			if install_ok:
				try:
					if settings.changeInstalledOption(self.service_name, self.name, True):
						output.printSuccess('Tool {0} has been marked as installed. '.format(self.name))
					else:
						output.printError('Error when saving "{0}{1}" configuration file'.format(Constants.INSTALL_STATUS_CONF_FILE, Constants.CONF_EXT))
				except Exception as e:
					output.printError('An unexpected error occured when trying to mark the tool as installed: {0}'.format(e))
					self.removeTool(settings, output)
			else:
				output.printFail('Tool {0} has not been marked as installed'.format(self.name))
				self.removeTool(settings, output)
		else:
			output.printFail('Tool has not been installed')
		print


	def checkInstall(self, output, referencing_tool=None):
		"""
		Check if the tool is correctly installed.
		Basically, it runs the installed tool without any option

		@Args		output: 	CLIOutput instance
		@Returns	Boolean indicating status
		"""

		output.printInfo('Trying to run the tool {0} with no option...'.format(self.name))
		if referencing_tool:
			cmd, cmd_short = referencing_tool.command.getParsedCmdline(remove_args=True)
		elif self.command:
			cmd, cmd_short = self.command.getParsedCmdline(remove_args=True)
		else:
			raise Exception

		output.printBeginCmd(cmd_short)
		process = ProcessLauncher(cmd, output, None)
		process.start()
		output.printEndCmd()

		output.printPrompt('Does the tool {0} seem to be running correctly ? [Y/n]'.format(self.name))
		return CLIUtils.promptYesNo(output, default='Y')


	def runUpdate(self, settings, output, fast_mode=False, referencing_tool=None):
		"""
		Run the update for the tool 

		@Args		settings: 	Settings instance
					output: 	CLIOutput instance
		@Returns	Boolean indicating status
		"""

		# Check for cases where no update will be run
		if not self.installed:
			output.printInfo('{0} is not installed yet (according to config), skipped.'.format(self.name))
			print
			return False

		elif self.tooltype == ToolType.USE_MULTI:
			output.printInfo('This is a reference to the tool "{0}", which is not specific to the service {1}'.format(self.tool_ref_name, self.service_name))
			ref_tool = settings.toolbox.searchInToolboxForService(self.tool_ref_name, Constants.MULTI_SERVICES_CONF_FILE)
			if ref_tool:
				return ref_tool.runUpdate(settings, output, fast_mode=fast_mode, referencing_tool=self)
			else:
				output.printFail('The tool "{0}" has not been found inside the conf file "{1}{2}"'.format(self.tool_ref_name, \
					Constants.MULTI_SERVICES_CONF_FILE, Constants.CONF_EXT))
				return False

		elif not self.update:
			output.printWarning('No tool update command specified in config file, skipped.')
			print
			return False

		# Create directory for the tool if necessary (should not be necessary because only update)
		if not FileUtils.is_dir(self.tool_dir):
			output.printFail('Tool directory does not exist but tool marked as installed. Trying to re-install it...')
			return self.runInstall(settings, output, fast_mode)

		# Print basic info and prompt confirmation
		cmd, cmd_short = self.update.getParsedCmdline()
		output.printInfo('Description     : {0}'.format(self.description))
		output.printInfo('Install command : {0}'.format(cmd_short))
		if not fast_mode: output.printPrompt('Update ? [Y/n]')

		# Run update command if wanted
		if fast_mode or CLIUtils.promptYesNo(output, default='Y'):
			output.printBeginCmd(cmd_short)
			process = ProcessLauncher(cmd, output, None)
			process.start()
			output.printEndCmd()
			output.printSuccess('Tool update has finished')

			# Check install ?
			update_ok = True
			if not (self.tooltype == ToolType.MULTI_SERVICES and not referencing_tool) and not fast_mode:
				output.printInfo('Now, checking if {0} has been updateed correctly. Hit any key to run test...'.format(self.name))
				CLIUtils.getch()
				try:
					update_ok = self.checkInstall(output, referencing_tool=referencing_tool)
				except Exception as e:
					update_ok = False
					output.printError('An unexpected error occured when checking install: {0}'.format(e))

			# Change install status in configuration file
			if update_ok:
				try:
					if settings.changeInstalledOption(self.service_name, self.name, True):
						output.printSuccess('Tool {0} has been marked as successfully updated'.format(self.name))
					else:
						output.printError('Error when saving "{0}{1}" configuration file'.format(Constants.INSTALL_STATUS_CONF_FILE, Constants.CONF_EXT))
				except Exception as e:
					output.printError('An unexpected error occured when trying to change the last update date: {0}'.format(e))
					#self.removeTool(settings, output)
			else:
				output.printFail('Tool {0} has not been marked as updated'.format(self.name))
				#self.removeTool(settings, output)
				output.printPrompt('Do you want to try to re-install {0} ? [Y/n]'.format(self.name))
				if CLIUtils.promptYesNo(output, default='Y'):
					self.reinstallTool(settings, output, referencing_tool=referencing_tool)
		else:
			output.printFail('Tool has not been updated')
		print


	def runTool(self, 
				settings, 
				output, 
				output_dir, 
				target, 
				specific_args, 
				ignore_specific=False,
				auto_yes=False):
		"""
		Run the tool

		@Args		settings: 		instance of Settings
					output: 		instance of CLIOutput
					output_dir:		directory where tool execution output will be saved
					target:			instance of Target
					specific_args:	specific arguments
					always_run: 	boolean indicating if tool should be always run (ignoring context specific options)
					auto_yes: 		boolean indicating if prompt should be displayed or not before running
		@Returns	Boolean indicating status
		"""
		# Tool not installed yet
		if not self.installed:
			output.printInfo('{0} is not installed yet (according to config), skipped.'.format(self.name))
			return False

		# If context specific
		if self.specific_options:
			for opt in self.specific_options.keys():
				# Boolean option
				if self.specific_options[opt][0] == bool:
					if self.specific_options[opt][1] == True and (opt not in specific_args.keys() or specific_args[opt] == False):
						output.printInfo('Tool skipped. Specific to: {0} = True'.format(opt))
						return False

				# List option
				elif self.specific_options[opt][0] == list and self.specific_options[opt][1]: 
					if opt not in specific_args.keys() or \
					   specific_args[opt] != 'all' and specific_args[opt] not in self.specific_options[opt][1]:
						output.printInfo('Tool skipped. Specific to: {0} = {1}'.format(opt, ', '.join(self.specific_options[opt][1])))
						return False

		# Print basic info and prompt confirmation
		cmd, cmd_short = self.command.getParsedCmdline(output_dir=output_dir, 
													   output_filename=self.name+'.txt',
													   target=target,
													   specific_args=specific_args)
		output.printInfo('Description : {0}'.format(self.description))
		output.printInfo('Run command : {0}'.format(cmd_short))
		if not auto_yes: 
			output.printPrompt('Run tool ? [Y/n/t/w/q]'.format(self.category, self.name))
			to_run = CLIUtils.promptRunMode(output, default='Y')

		# Run command if wanted
		if to_run == 'Quit':
			print
			output.printWarning('Exit !')
			sys.exit(0)
		elif to_run != 'No':
			output.printBeginCmd(cmd_short)
			process = ProcessLauncher(cmd, output, None)			
			# Normal running
			if auto_yes or to_run == 'Yes':
				process.start()

			# Start in new tab
			elif to_run == 'Tab':
				# TODO
				output.printInfo('Not yet implemented')

			# Start in new window
			elif to_run == 'Window':
				process.startInNewWindow()
				print
				output.printInfo('Started in another window')
			output.printEndCmd()
		print	


	def removeTool(self, settings, output):
		"""
		Remove the tool:
			- Remove tool directory into toolbox
			- Change install status to false
		
		@Args		settings: 	Settings instance
					output: 	CLIOutput instance
		@Returns	Boolean indicating operation status
		"""

		if self.tooltype == ToolType.USE_MULTI:
			output.printInfo('"{0}" is a reference to the tool "{1}" used for multi services. Not deleted'.format(\
				self.name, self.tool_ref_name))
			return False

		if not FileUtils.is_dir(self.tool_dir):
			output.printInfo('Directory "{0}" does not exist'.format(self.tool_dir))
		else:
			if not FileUtils.remove_directory(self.tool_dir):
				output.printFail('Unable to delete directory "{0}". Check permissions and/or re-run with sudo'.format(self.tool_dir))
				return False
			else:
				output.printInfo('Directory "{0}" deleted'.format(self.tool_dir))

		# Make sure "installed" option in config file is set to False
		if not settings.changeInstalledOption(self.service_name, self.name, False):
			output.printError('An unexpected error occured when trying to mark the tool as uninstalled !')
		self.installed = False
		return True


	def reinstallTool(self, settings, output, referencing_tool=None):
		"""
		Try a tool re-install, i.e. remove and install

		@Args		settings: 	Settings instance
					output: 	CLIOutput instance
		@Returns	Boolean indicating operation status
		"""
		output.printInfo('First, the tool directory will be removed...')
		if not self.removeTool(settings, output):
			return False
		output.printInfo('Now, running a new install for {0}...'.format(self.name))
		return self.runInstall(settings, output, referencing_tool=referencing_tool)
