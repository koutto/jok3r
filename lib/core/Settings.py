###
### Settings 
###
import sys
import ConfigParser
import traceback
from datetime import datetime
from lib.utils.DefaultConfigParser import DefaultConfigParser
from lib.utils.FileUtils import FileUtils
from lib.core.Constants import *
from lib.core.Toolbox import Toolbox
from lib.core.Tool import Tool


class Settings(object):

	def __init__(self, settings_dir, toolbox_dir, output):
		"""
		Constructor of Settings object
		@Args		settings_dir: 	directory where config files are stored
					toolbox_dir: 	directory where the toolbox is stored
					output: 		Instance of CLIOutput
		"""
		self.settings_dir 		= settings_dir
		self.toolbox_dir 		= toolbox_dir
		self.output 	 		= output
		# config_parsers: dict of config_parsers indexed by service_name
		self.config_parsers     = {}
		# general_settings: 2 dimensions dict - [service_name][setting]
		self.general_settings	= {}
		self.toolbox 			= Toolbox(self)

		# Check directory and presence of *.conf files
		if not FileUtils.is_dir(settings_dir):
			self.output.printError('Configuration directory ({0}) does not exist'.format(settings_dir))
			sys.exit(0)

		files = FileUtils.list_directory(settings_dir)
		for f in files:
			if not FileUtils.check_extension(f, CONF_EXT):
				files.remove(f)
		if not files:
			self.output.printError('Configuration directory ({0}) does not store any *.conf file'.format(settings_dir))
			sys.exit(0)

		# Parse config files
		# i.e. extract tools categories and optional/specific settings for each service
		self.parseConfFiles(files)


	def parseConfFiles(self, files):
		"""
		Parse all *.conf files into the config directory
		@Args		files: 	list of config files to parse
		@Returns 	None
		"""
		# Process *.conf files
		for f in files:
			self.output.printInfo('Parsing configuration file "{0}" ...'.format(f))

			full_path = FileUtils.concat_path(self.settings_dir, f)
			service_name = f[:f.rfind(CONF_EXT)].lower().strip()
			self.config_parsers[service_name] = DefaultConfigParser()
			self.config_parsers[service_name].read(full_path)
			#config_parser = DefaultConfigParser()
			#config_parser.read(full_path)

			# Add the entry into general settings for the service
			self.general_settings[service_name] = {}

			# General settings - [general] in .conf file
			self.general_settings[service_name]['tools_categories'] = [ e.lower() for e in self.config_parsers[service_name].safeGetList('general', 'tools_categories', ',', []) ]

			# General settings - Optional/Specific settings (depends on the targeted servicee) 
			if service_name in SPECIFIC_TOOL_OPTIONS.keys():
				for option in SPECIFIC_TOOL_OPTIONS[service_name]:
					if SPECIFIC_TOOL_OPTIONS[service_name][option]:
						setting_name = SPECIFIC_TOOL_OPTIONS[service_name][option]
						self.general_settings[service_name][setting_name] = \
							[ e.lower() for e in self.config_parsers[service_name].safeGetList('general', setting_name, ',', []) ]

			# Check general settings for the current service
			self.checkGeneralSettings(service_name)

			# Add service as new toolbox section
			self.toolbox.addService(service_name)

			# Add tools in current config file into the toolbox, under the correct service section
			for section in self.config_parsers[service_name].sections():
				if section.startswith('tool_'):
					newtool = self.createToolFromConfiguration(section, service_name)
					if newtool:
						if not self.toolbox.addTool(newtool, service_name):
							self.output.printWarning('Unable to add tool "{0}" into the toolbox'.format(newtool.name))
					else:
						#self.output.printSettings('Tool "{0}" added into the toolbox (category "{1}")'.format(newtool.name, 
						#	newtool.category))
						pass


	def checkGeneralSettings(self, service_name):
		"""
		Check [general] section
		@Args		service_name: 	service related to config file to check
		@Returns	Boolean indicating status
		"""
		if service_name not in self.general_settings.keys():
			return False

		# General settings - [general] in .conf file
		if not self.general_settings[service_name]['tools_categories']:
			self.output.printError('[{0}{1}] General settings error: Incorrect "tools_categories"'.format(service_name, CONF_EXT))
			sys.exit(0)

		# General settings - Optional/Specific settings (depends on the targeted servicee) 
		if service_name in SPECIFIC_TOOL_OPTIONS.keys():
			for option in SPECIFIC_TOOL_OPTIONS[service_name]:
				if SPECIFIC_TOOL_OPTIONS[service_name][option]:
					setting_name = SPECIFIC_TOOL_OPTIONS[service_name][option]
					if not self.general_settings[service_name][setting_name]:
						self.output.printWarning('[{0}{1}] General settings warning: No "{2}" setting for service {3}.' + \
							'The tool option "{4}" will not be taken into account'.format( \
								service_name, CONF_EXT, setting_name, service_name, option))
		return True


	def createToolFromConfiguration(self, section, service_name):
		"""
		Create tool object from a [tool_****] entry into the settings file
		@Args		section: 		section from config file corresponding to a tool
					service_name: 	service targeted by the tool
		@Returns	instance of Tool object if everything is ok, False otherwise
		"""
		if service_name not in self.general_settings.keys():
			return False

		# First, check for the presence of all needed option for the tool
		options = self.config_parsers[service_name].options(section)
		for o in MANDATORY_TOOL_OPTIONS:
			if o not in options:
				self.output.printWarning('[{0}{1}] Section "{2}" > missing mandatory option "{3}", skipped'.format( \
					service_name, CONF_EXT, section, o))
				return False

		# Parse general+mandatory info
		try:
			name        = self.config_parsers[service_name].safeGet(section, 'name', '', None).strip()
			category    = self.config_parsers[service_name].safeGet(section, 'category', '', None).strip().lower()
			description = self.config_parsers[service_name].safeGet(section, 'description', '', None).strip()
			raw_command = self.config_parsers[service_name].safeGet(section, 'command', '', None).strip()
		except:
			self.output.printWarning('[{0}{1}] Section "{2}" > syntax error with mandatory options'.format( \
				service_name, CONF_EXT, section))
			#traceback.print_exc()
			return False

		# Check general+mandatory info
		if not name:
			self.output.printWarning('[{0}{1}] Section "{2}" > option "name" is empty, section skipped'.format(service_name, CONF_EXT, section))
			return False
		if not category:
			self.output.printWarning('[{0}{1}] Section "{2}" > option "category" is empty, section skipped'.format(service_name, CONF_EXT, section))
			return False
		if category not in self.general_settings[service_name]['tools_categories']:
			self.output.printWarning('[{0}{1}] Section "{2}" > option "category" ("{3}") not in "tools_categories",' + \
				' section skipped'.format(service_name, CONF_EXT, section, category))
			return False
		if not raw_command:
			self.output.printWarning('[{0}{1}] Section "{2}" > option "command" is empty, section skipped'.format(service_name, CONF_EXT, section))
			return False

		# Parse general+optional info
		try:
			install 		= self.config_parsers[service_name].safeGet(section, 'install', '', None).strip()
			update 			= self.config_parsers[service_name].safeGet(section, 'update', '', None).strip()
			last_update 	= self.config_parsers[service_name].safeGet(section, 'last_update', '', None).strip()
			installed 		= self.config_parsers[service_name].safeGetBoolean(section, 'installed', True)
		except:
			pass

		# Parse specific info (depends on targeted service)
		# opt_specific is a dictionary: "option" => (type, value)
		opt_specific    = dict()
		if service_name in SPECIFIC_TOOL_OPTIONS.keys():
			for option in SPECIFIC_TOOL_OPTIONS[service_name]:
				# Boolean options (default False)
				if SPECIFIC_TOOL_OPTIONS[service_name][option] == '':
					opt_specific[option] = (bool, self.config_parsers[service_name].safeGetBoolean(section, option + '_specific', False))

				# List-type options
				else:
					value_list = [ e.lower() for e in self.config_parsers[service_name].safeGetList(section, option + '_specific', ',', []) ]
					if value_list:
						for e in value_list:
							if e.lower() not in self.general_settings[service_name][SPECIFIC_TOOL_OPTIONS[service_name][option]]:
								value_list.remove(e)
								self.output.printWarning('[{0}{1}] Section "{2}" > option "{3}" contains invalid entry ' + \
									'("{4}")'.format(service_name, CONF_EXT, section, option, e))
					opt_specific[option] = (list, value_list)

		# Create the Tool object from parsed info
		tool = Tool(service_name,
					section,
					self.toolbox_dir,
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
					opt_specific)

		return tool


	def changeInstalledOption(self, service_name, tool_section_name, value):
		"""
		Change the status of option "installed" for a given tool
		@Args		service_name: 		service targeted by the tool
					tool_section_name: 	Tool section name as it appears in config file
					value: 				'True' if tool installed, 'False' otherwise
		@Returns	Boolean indicating operation status
		"""
		if value not in ('True', 'False'):
			return False
		if self.config_parsers[service_name].safeSet(tool_section_name, 'installed', value):
			return self.saveSettings(service_name)
		return False


	def changeLastUpdateOption(self, service_name, tool_section_name):
		"""
		Update the value of the option "last_update" with the current date-time
		@Args		service_name: 		service targeted by the tool
					tool_section_name: 	Tool section name as it appears in config file	
		@Returns	Boolean indicating operation status	
		"""
		current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		if self.config_parsers[service_name].safeSet(tool_section_name, 'last_update', current_datetime):
			return self.saveSettings(service_name)
		return False


	def saveSettings(self, service_name):
		"""
		Save settings into config file.
		Make sure changes are thus taken into account.
		@Args		service_name: service targeted by the tool
		@Returns	Boolean indicating operation status
		"""
		try:
			config_file = FileUtils.concat_path(self.settings_dir, service_name + '.conf')
			with open(config_file, 'w') as handle:
				self.config_parsers[service_name].write(handle)
				# Re-read to take change into account
				self.config_parsers[service_name].read(config_file) # warning: takes filename as param
			return True
		except:
			traceback.print_exc()
			return False		
