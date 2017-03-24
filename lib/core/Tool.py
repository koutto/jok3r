###
### Tool
###

import os
import subprocess
import sys
from lib.utils.FileUtils import FileUtils
from lib.utils.CLIUtils import CLIUtils
from lib.core.Constants import *
from lib.core.ProcessLauncher import ProcessLauncher
from lib.core.Command import Command


# -----------------------------------------------------------------------------
# Options for tools entries in settings file:
# -----------------------------------------------------------------------------
#
# General+Mandatory tool options:
# --------------------------------
# name 				(String | mandatory) Name of the tool as it will appear in program
# category			(String | mandatory) Must be one of the categories in "tools_categories"
# description		(String | mandatory) Short description for the tool
# command 			(String | mandatory) Command-line used to launch the tool (see tags that can be used below)
#
# General+Optional tool options:
# ------------------------------
# install			(String | optional) Tool installation command
# update			(String | optional) Tool update command
# last_update		(String | optional) Date of last update (value updated by jok3r)
# installed			(Boolean | optional | default: True) Indicates if tool installed (value updated by jok3r)
# 
# Specific tool options (example with http service):
# --------------------------------------------------
# ssl_specific		(Boolean | optional | default: False) True if tool must be launched ONLY when SSL in use 
# server_specific	(String/list | optional) If tool is launched ONLY for specific server (in "server_list")
# techno_specific	(String/list | optional) If tool is launched ONLY for specific technology (in "techno_list")
# cms_specific		(String/list | optional) If tool is launched ONLY for specific cms (in "cms_list")
#


class Tool(object):

	def __init__(self, 
				 service_name,
				 section_name,
				 toolbox_dir,
				 # General+Mandatory tool options
				 name,
				 category,
				 description,
				 raw_command,
				 # General+Optional tool options
				 install,
				 update,
				 last_update,
				 installed,
				 # Specific tool options
				 specific_options):
		"""
		Tool constructor
		@Args		service_name:		service targeted by the tool (mandatory),
					section_name:		section name as it appears in the config file (mandatory)
					toolbox_dir:		toolbox directory
					name:				tool name as it will appear in the program (mandatory)
					category:			tool category, must be one of the categories in "tools_categories" general setting (mandatory)
					description: 		tool description, it will be diplayed to user before running tool (mandatory)
					raw_command:		command-line used to launched the tool (can use tags) (mandatory)
					install:			command-line for tool install
					update:				command-line for tool update
					last_update:		date of last tool update
					installed:			boolean indicating whether tool is installed or not
					specific_options:	dictionary of specific tool options
		"""

		self.service_name	 	= service_name
		self.section_name    	= section_name
		self.toolbox_dir	 	= toolbox_dir

		self.name 			 	= name
		self.category 		 	= category
		self.description 	 	= description
		self.command 		 	= raw_command

		self.install 		 	= install
		self.update 		 	= update
		self.last_update 	 	= last_update
		self.installed 		 	= installed if isinstance(installed, bool) else False

		self.specific_options 	= specific_options		

		# Directory reserved for the tool
		clean_name 			 = "".join(c for c in self.name 	if c.isalnum() or c in ('_','-',' ')).lower().strip()
		clean_category  	 = "".join(c for c in self.category if c.isalnum() or c in ('_','-',' ')).lower().strip()
		self.tool_dir 	     = self.toolbox_dir + os.sep + self.service_name + os.sep + clean_category + os.sep + clean_name


	def printToolSummary(self, output):
		"""
		Print tool info nicely
		@Args		output: CLIOutput instance
		@Returns	None
		"""

		output.printTitle1('   ' + self.name)
		output.printNewLine('     Description : {0}'.format(self.description))
		output.printNewLine('     Command     : {0}'.format(self.command))
		output.printRaw('     Installed   : ')   
		if self.installed:
			output.printGreen('Yes\n')
		else:
			output.printRed('No\n')
		output.printNewLine('     Location    : {0}'.format(self.tool_dir))
		output.printNewLine('     Last update : {0}'.format(self.last_update if self.last_update else 'Unknown'))
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
		@Returns	None
		"""
		if self.installed:
			output.printGreen('   - {0}\n'.format(self.name))
		else:
			output.printRed('   - {0}\n'.format(self.name))


	def createToolDirectory(self, output):
		"""
		Create the tool reserved directory if necessary
		@Args		output: 	CLIOutput instance
		@Returns	Boolean indicating if dir was successfully created
		"""
		# if FileUtils.is_dir(self.tool_dir):
		# 	if not FileUtils.remove_directory(self.tool_dir):
		# 		output.printFail('Unable to delete directory \'{0}\'. Check permissions and/or re-run with sudo.'.format(self.tool_dir))
		# 	else:
		# 		output.printInfo('Directory \'{0}\' deleted'.format(self.tool_dir))
		if FileUtils.is_dir(self.tool_dir):
			output.printInfo('Directory \'{0}\' already exists'.format(self.tool_dir))
			return True

		try:
			FileUtils.create_directory(self.tool_dir)
		except Exception as e:
			output.printError('Unable to create new directory \'{0}\': {1}.'.format(self.tool_dir, e))
			return False
		output.printInfo('New directory \'{0}\' created'.format(self.tool_dir))
		return True


	def runInstall(self, settings, output):
		"""
		Install the tool
		@Args		settings: 	Settings instance
					output: 	CLIOutput instance
		@Returns	Boolean indicating status
		"""

		# Tool already marked as installed
		if self.installed:
			#if not FileUtils.is_dir(self.tool_dir):
			#	output.printInfo('{0} marked as installed in config, but directory does not exist. Will try to install it'.format(self.name))
			# elif FileUtils.is_directory_empty(self.tool_dir):
			# 	output.printInfo('{0} marked as installed in config, but directory empty. Will try to install it'.format(self.name))
			#else:
			output.printInfo('{0} is already installed (according to config), skipped.'.format(self.name))
			print
			return False

		# Not installed, but no install command specified
		elif not self.install:
			output.printWarning('No tool install command specified in config file, skipped.')
			output.printPrompt('Do you want to mark this tool as installed ? [y/N]')
			to_mark = CLIUtils.promptYesNo(output, default='N')
			if to_mark:
				if not settings.changeInstalledOption(self.service_name, self.section_name, 'True'):
					output.printError('An unexpected error occured when trying to mark the tool as installed !')
				else:
					output.printSuccess('Tool {0} has been marked as installed. '.format(self.name))
			else:
				output.printInfo('Tool is still not marked as installed')
			print
			return False

		# Create directory for the tool if necessary
		if not self.createToolDirectory(output):
			output.printFail('Tool install skipped.')
			print
			return False

		# Install command parsing
		cmd_install = self.getInstallCmd()	
		cmd_install_print = cmd_install[cmd_install.index(';')+1:].strip()	
		output.printInfo('Install Command:')
		output.printInfo(cmd_install_print)
		output.printPrompt('{0} > {1} - Install ? [Y/n]'.format(self.category, self.name))

		# Prompt
		to_install = CLIUtils.promptYesNo(output, default='Y')

		# Run install command if wanted
		if to_install:
			output.printBeginCmd(cmd_install)
			process = ProcessLauncher(cmd_install, output, None)
			process.start()
			output.printEndCmd()

			output.printSuccess('Tool installation has finished')
			output.printInfo('Now, checking if {0} has been installed correctly. '.format(self.name) + \
				'Hit any key to run test...')
			CLIUtils.getch()

			# Check install, update config options
			if self.checkInstall(output):
				if not settings.changeInstalledOption(self.service_name, self.section_name, 'True'):
					output.printError('An unexpected error occured when trying to mark the tool as installed !')
				else:
					output.printSuccess('Tool {0} has been marked as installed. '.format(self.name))
					if not settings.changeLastUpdateOption(self.service_name, self.section_name):
						output.printWarning('An unexpected error occured when trying to change last update date')
			else:
				output.printFail('Tool {0} is still not marked as installed.'.format(self.name))
				self.removeTool(settings, output)
		else:
			output.printFail('Tool has not been installed')

		print


	def checkInstall(self, output):
		"""
		Check if the tool is correctly installed.
		Basically, it runs the installed tool without any option
		@Args		output: 	CLIOutput instance
		@Returns	Boolean indicating status
		"""

		# Directory where the tool should be installed
		if not FileUtils.is_dir(self.tool_dir):
			output.printFail('Directory where the tool should be installed (\'{0}\') does not exist !'.self.tool_dir)
			return False

		# Try to run the tool
		output.printInfo('Trying to run the tool {0}...'.format(self.name))
		splitted = self.command.strip().split(' ')
		cmd = splitted[0]
		if cmd.lower() in ('python', 'python3', 'perl', 'ruby') and len(splitted) > 1:
			if splitted[1] != '-m':
				cmd += ' {0}'.format(splitted[1])
			elif len(splitted) > 2:
				cmd += ' -m {0}'.format(splitted[2])

		elif cmd.lower() == 'java' and len(splitted) > 2:
			if splitted[1].lower() == '-jar':
				cmd += ' -jar {0}'.format(splitted[2])
				
	 	c = Command(self.tool_dir, cmd, None, self.toolbox_dir, None, None, None, None)
		cmd_check = c.getStandardCommandLine()
		cmd_check_print = cmd_check[cmd_check.index(';')+1:].strip()

		output.printBeginCmd(cmd_check_print)
		process = ProcessLauncher(cmd_check, output, None)
		process.start()
		output.printEndCmd()

		# Prompt 
		output.printPrompt('Does the tool {0} seem to be running correctly ? [Y/n]'.format(self.name))
		return CLIUtils.promptYesNo(output, default='Y')


	def runUpdate(self, settings, output):
		"""
		Run the update for the tool 
		@Args		settings: 	Settings instance
					output: 	CLIOutput instance
		@Returns	Boolean indicating status
		"""
		# Tool not installed yet
		if not self.installed:
			output.printInfo('{0} is not installed yet (according to config), skipped.'.format(self.name))
			print
			return False

		# Not installed, but no update command specified
		elif not self.update:
			output.printWarning('No tool update command specified in config file, skipped.')
			print
			return False

		# Create directory for the tool if necessary (should not be necessary because only update)
		if not FileUtils.is_dir(self.tool_dir):
			output.printFail('Tool directory does not exist but tool marked as installed. Trying to re-install it...')
			return self.runInstall(settings, output)

		# Update command parsing
		cmd_update = self.getUpdateCmd()
		cmd_update_print = cmd_update[cmd_update.index(';')+1:].strip()
		output.printInfo('Update Command:')
		output.printInfo(cmd_update_print)
		output.printPrompt('{0} > {1} - Update ? [Y/n]'.format(self.category, self.name))
		# Prompt
		to_update = CLIUtils.promptYesNo(output, default='Y')

		# Run update command if wanted
		if to_update:
			output.printBeginCmd(cmd_update_print)
			process = ProcessLauncher(cmd_update, output, None)
			process.start()
			output.printEndCmd()

			output.printSuccess('Tool update has finished')

			output.printInfo('Now, checking if {0} has been updated correctly. '.format(self.name) + \
				'Hit any key to run test...')
			CLIUtils.getch()

			# Check update, update config options
			if self.checkInstall(output):
				if not settings.changeLastUpdateOption(self.service_name, self.section_name):
					output.printWarning('An unexpected error occured when trying to last update date.')
				else:
					output.printSuccess('Tool {0} has been marked as successfully updated.'.format(self.name))
			else:
				# If test fails, ask user if re-install ?
				output.printFail('Tool {0} has not been marked as updated.'.format(self.name))
				output.printPrompt('Do you want to try to re-install {0} ? [Y/n]'.format(self.name))

				# Prompt
				to_reinstall = CLIUtils.promptYesNo(output, default='Y')

				# Re-Install
				if to_reinstall:
					self.reinstallTool(settings, output)
		else:
			output.printFail('Tool has not been updated')

		print


	def runTool(self, 
				settings, 
				output, 
				output_file, 
				output_dir, 
				target, 
				specific_args, 
				ignore_specific=False,
				auto_yes=False):
		"""
		Run the tool 
		@Args		settings: 		instance of Settings
					output: 		instance of CLIOutput
					output_file:	file where tool execution output will be saved
					output_dir:		some tools (e.g. skipfish) require an output dir where results are saved
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
					#elif self.specific_options[opt][1] == False and opt in specific_args.keys() and specific_args[opt] == True:
					#	output.printInfo('Tool skipped. Specific to: {0} = False'.format(opt))
					#	return False

				# List option
				elif self.specific_options[opt][0] == list and self.specific_options[opt][1]: 
					if opt not in specific_args.keys() or \
					   specific_args[opt] != 'all' and specific_args[opt] not in self.specific_options[opt][1]:
						output.printInfo('Tool skipped. Specific to: {0} = {1}'.format(opt, ', '.join(self.specific_options[opt][1])))
						return False

		# Run command parsing
		cmd_run = self.getRunCmd(target, output_file, output_dir, specific_args)
		cmd_run_print = cmd_run[cmd_run.index(';')+1:].strip()
		output.printInfo('Command:')
		output.printInfo(cmd_run_print)
		if not auto_yes:
			output.printPrompt('Run tool ? [Y/n/t/w/q]'.format(self.category, self.name))
			# Prompt
			to_run = CLIUtils.promptRunMode(output, default='Y')

		# Run update command if wanted
		if auto_yes or to_run == 'Yes':
			output.printBeginCmd(cmd_run_print)
			process = ProcessLauncher(cmd_run, output, None)
			process.start()
			output.printEndCmd()
		elif to_run == 'Tab':
			#TODO
			pass
		elif to_run == 'Window':
			output.printBeginCmd(cmd_run_print)
			process = ProcessLauncher(cmd_run, output, None)
			process.startInNewWindow()
			print
			output.printInfo('Started in another window.')
			output.printEndCmd()
		elif to_run == 'Quit':
			print
			output.printWarning('Exit !')
			sys.exit(0)

		print	


	def removeTool(self, settings, output):
		"""
		Remove tool directory and all files it contains
		@Args		settings: Settings instance
					output: CLIOutput instance
		@Returns	Boolean indicating status
		"""

		if not FileUtils.is_dir(self.tool_dir):
			output.printInfo('Directory \'{0}\' does not exist'.format(self.tool_dir))
		else:
			if not FileUtils.remove_directory(self.tool_dir):
				output.printFail('Unable to delete directory \'{0}\'. Check permissions and/or re-run with sudo.'.format(self.tool_dir))
				return False
			else:
				output.printInfo('Directory \'{0}\' deleted'.format(self.tool_dir))

		# Make sure "installed" option in config file is set to False
		if not settings.changeInstalledOption(self.service_name, self.section_name, 'False'):
			output.printError('An unexpected error occured when trying to mark the tool as uninstalled !')
		self.installed = False
		return True


	def reinstallTool(self, settings, output):
		"""
		Try a tool re-install, ie. remove and install
		@Args		settings: Settings instance
					output: CLIOutput instance
		@Returns	Boolean indicating status
		"""
		output.printInfo('First, the tool directory will be removed...')
		if not self.removeTool(settings, output):
			return False
		output.printInfo('Now, running a new install for {0}...'.format(self.name))
		return self.runInstall(settings, output)
	

	def getInstallCmd(self):
		"""
		Build install command
		@Returns	Install command-line
		"""
		c = Command(self.tool_dir, self.install, None, self.toolbox_dir, None, None, None, None)
		return c.getParsedInstallCommandLine()


	def getUpdateCmd(self):
		"""
		Build update command
		@Returns	Update command-line
		"""
		c = Command(self.tool_dir, self.update, None, self.toolbox_dir, None, None, None, None)
		return c.getParsedInstallCommandLine()


	def getRunCmd(self, target, output_file, output_dir, specific_args):
		"""
		Build run command
		"""
		#print self.command
	 	c = Command(self.tool_dir, self.command, target, self.toolbox_dir, 
	 				output_file, output_dir, self.service_name, specific_args)
		return c.getParsedRunCommandLine()