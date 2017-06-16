###
### Settings 
###
import sys
import traceback
from datetime import datetime
from lib.utils.DefaultConfigParser import DefaultConfigParser
from lib.utils.FileUtils import FileUtils
from lib.utils.StringUtils import StringUtils
from lib.core.Constants import *
from lib.core.Toolbox import Toolbox
from lib.core.Tool import ToolType, Tool


class Settings(object):

	def __init__(self, settings_dir, toolbox_dir, output):
		"""
		Initialize Settings object

		@Args		settings_dir: 	directory where config files are stored
					toolbox_dir: 	directory where the toolbox is stored
					output: 		Instance of CLIOutput

		"""
		self.settings_dir 		= settings_dir
		self.toolbox_dir 		= toolbox_dir
		self.output 	 		= output

		# config_parsers: dict of config_parsers indexed by conf_filename
		self.config_parsers     = {}
		# general_settings: 2 dimensions dict - [service_name][option_name]
		self.general_settings	= {}
		self.toolbox 			= Toolbox(self)

		# Check directory and presence of *.conf files
		if not FileUtils.is_dir(settings_dir):
			self.output.printError('Configuration directory ({0}) does not exist'.format(settings_dir))
			raise ValueError

		files = FileUtils.list_directory(settings_dir)
		for f in files:
			if not FileUtils.check_extension(f, CONF_EXT):
				files.remove(f)
		if not files:
			self.output.printError('Configuration directory ({0}) does not store any *.conf file'.format(settings_dir))
			raise ValueError

		# Parse config files
		self.parseAllConfFiles(files)


	def parseAllConfFiles(self, files):
		"""
		Parse all *.conf files into the config directory
		@Args		files: 	list of config files to parse
		@Returns 	None
		"""
		# ----
		# Parse INSTALL_STATUS_CONF_FILE
		if INSTALL_STATUS_CONF_FILE+CONF_EXT not in files:
			self.output.printError('Install status file ({0}/{1}.{2}) is missing'.format(SETTINGS_DIR, INSTALL_STATUS_CONF_FILE, CONF_EXT))
			sys.exit(0)

		self.config_parsers[INSTALL_STATUS_CONF_FILE] = DefaultConfigParser()
		self.config_parsers[INSTALL_STATUS_CONF_FILE].read(FileUtils.concat_path(self.settings_dir, INSTALL_STATUS_CONF_FILE+CONF_EXT))
		files.remove(INSTALL_STATUS_CONF_FILE+CONF_EXT)

		# ----
		# Parse MULTI_SERVICES_CONF_FILE
		support_multi_services_tools = MULTI_SERVICES_CONF_FILE+CONF_EXT in files
		self.parseToolsConfFile(MULTI_SERVICES_CONF_FILE+CONF_EXT)
		files.remove(MULTI_SERVICES_CONF_FILE+CONF_EXT)
	
		# ----
		# Parse services *.conf files
		for f in files:
			self.parseToolsConfFile(f)


	def parseToolsConfFile(self, file):
		"""
		Parse a given settings file
		"""
		#self.output.printInfo('Parsing configuration file "{0}" ...'.format(file))

		full_path 		= FileUtils.concat_path(self.settings_dir, file)
		conf_filename 	= FileUtils.remove_ext(file).lower().strip()

		self.config_parsers[conf_filename] = DefaultConfigParser()
		self.config_parsers[conf_filename].read(full_path)

		# Add the entry into general settings for the service
		self.general_settings[conf_filename] = {}

		if conf_filename == MULTI_SERVICES_CONF_FILE:
			self.general_settings[conf_filename]['tools_categories'] = ['all']

		else:
			# General settings - [general] in .conf file
			tools_cats = self.config_parsers[conf_filename].safeGetList('general', 'tools_categories', ',', [])
			self.general_settings[conf_filename]['tools_categories'] = [ StringUtils.cleanSpecialChars(e).lower() for e in tools_cats ]

			# General settings - Optional/Specific settings (depends on the targeted service) 
			if conf_filename in SPECIFIC_TOOL_OPTIONS.keys():
				for option in SPECIFIC_TOOL_OPTIONS[conf_filename]:
					setting_name = SPECIFIC_TOOL_OPTIONS[conf_filename][option]
					if setting_name:
						self.general_settings[conf_filename][setting_name] = \
							[ e.lower() for e in self.config_parsers[conf_filename].safeGetList('general', setting_name, ',', []) ]

			# Check general settings for the current service
			self.checkGeneralSettings(conf_filename)

		# Add service as new toolbox section
		self.toolbox.addService(conf_filename)

		# Add tools in current config file into the toolbox, under the correct service section
		for section in self.config_parsers[conf_filename].sections():
			if section.startswith(PREFIX_TOOL_SECTIONNAME):
				if conf_filename != MULTI_SERVICES_CONF_FILE:
					newtool = self.createToolFromConfiguration(section, conf_filename, tooltype=ToolType.STANDARD)
				else:
					newtool = self.createToolFromConfiguration(section, conf_filename, tooltype=ToolType.MULTI_SERVICES)

			elif section.startswith(PREFIX_TOOL_USEMULTI_SECTIONNAME):
				newtool = self.createToolFromConfiguration(section, conf_filename, tooltype=ToolType.USE_MULTI)
			else:
				continue


			if newtool:
				if not self.toolbox.addTool(newtool, conf_filename):
					self.output.printWarning('Unable to add tool "{0}" into the toolbox'.format(newtool.name))
			else:
				#self.output.printSettings('Tool "{0}" added into the toolbox (category "{1}")'.format(newtool.name, 
				#	newtool.category))
				pass				


	def checkGeneralSettings(self, service_name):
		"""
		Check [general] section in settings files

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
						self.output.printWarning('[{0}{1}] General settings warning: No "{2}" setting for service {3}. The tool option "{4}" will not be taken into account'.format( \
							service_name, CONF_EXT, setting_name, service_name, option))
		return True


	def createToolFromConfiguration(self, section, service_name, tooltype=ToolType.STANDARD):
		"""
		Create tool object from a tool entry (section) into the settings file
		Note: Must be called after initializing parser for INSTALL_STATUS_CONF_FILE

		@Args		section: 		Section from config file corresponding to a tool
					service_name: 	Service targeted by the tool
					tooltype: 		ToolType
		@Returns	instance of Tool object if everything is ok, False otherwise

		"""
		if service_name not in self.general_settings.keys():
			return False

		# Parse general options
		options_general = self.parseToolGeneralOptions(section, service_name, tooltype)
		if not options_general:
			return False
	

		# Parse specific info (depends on targeted service)
		options_specific = self.parseToolSpecificOptions(section, service_name, tooltype)

		# Create the Tool object from parsed info
		tool = Tool(service_name,
					self.toolbox_dir,
					tooltype,
					# General tool options
					options_general['name'],
					options_general['tool_ref_name'],
					options_general['category'],
					options_general['description'],
					options_general['command'],
					options_general['install'],
					options_general['update'],
					options_general['installed'],
					options_general['last_update'],
					# Specific tool options	
					options_specific)
		return tool


	def parseToolGeneralOptions(self, section, service_name, tooltype=ToolType.STANDARD):
		"""
		Parse the general options inside a tool section in settings file.
		General options include:
			- Mandatory options (depends on the tooltype), defined inside Constants.py
			- Optional options: install, update
			- Install status: extracted from INSTALL_STATUS_CONF_FILE

		@Args		section: 		Section from config file corresponding to a tool
					service_name: 	Service targeted by the tool
					tooltype: 		ToolType

		@Returns	If success: 	Dictionary options_general
					If error: 		None

		"""

		options_general	= {'name'			: '',
						   'tool_ref_name'	: '',
						   'category'		: '',
						   'description'	: '',
						   'command'		: '',
						   'install'		: '',
						   'update'			: '',
						   'installed'		: False,
						   'last_update'	: ''}

		# ----
		# Check presence of mandatory options
		for o in MANDATORY_TOOL_OPTIONS[tooltype]:
			if o not in self.config_parsers[service_name].options(section):
				self.output.printWarning('[{0}{1}] Section "{2}" > missing mandatory option "{3}", skipped'.format(service_name, CONF_EXT, section, o))
				return None

		# ----
		# Parse mandatory options
		try:
			for o in MANDATORY_TOOL_OPTIONS[tooltype]:
				options_general[o] = self.config_parsers[service_name].safeGet(section, o, '', None).strip()
				if o == 'name' or o == 'tool_ref_name':
					options_general[o] = StringUtils.cleanSpecialChars(options_general[o])
				if o == 'category':
					options_general[o] = StringUtils.cleanSpecialChars(options_general[o]).lower()
		except:
			self.output.printWarning('[{0}{1}] Section "{2}" > syntax error with mandatory options'.format(service_name, CONF_EXT, section))
			return None

		if tooltype == ToolType.MULTI_SERVICES:
			options_general['category'] = 'all'

		# ----
		# Check mandatory options
		for o in MANDATORY_TOOL_OPTIONS[tooltype]:
			if not options_general[o]:
				self.output.printWarning('[{0}{1}] Section "{2}" > option "{3}" is empty, section skipped'.format(service_name, CONF_EXT, section, o))
				return None
		if options_general['category'] not in self.general_settings[service_name]['tools_categories']:
			self.output.printWarning('[{0}{1}] Section "{2}" > option "category" ("{3}") not in "tools_categories", section skipped'.format(service_name, CONF_EXT, section, category))
			return None

		# ----
		# Parse general+optional options
		try:
			options_general['install'] = self.config_parsers[service_name].safeGet(section, 'install', '', None).strip()
			options_general['update']  = self.config_parsers[service_name].safeGet(section, 'update', '', None).strip()
		except:
			pass

		# ----
		# Retrieve install status
		# By default: not installed, no last update date

		# If the tool entry is actually a reference to a multi-services tool, extract the install status
		# from [multi] section inside INSTALL_STATUS_CONF_FILE
		if tooltype == ToolType.USE_MULTI:
			tool_installed = self.config_parsers[INSTALL_STATUS_CONF_FILE].safeGet(MULTI_SERVICES_CONF_FILE, options_general['tool_ref_name'], 'false', None).lower().strip()
		else:
			tool_installed = self.config_parsers[INSTALL_STATUS_CONF_FILE].safeGet(service_name, options_general['name'], 'false', None).lower().strip()

		if tool_installed == 'false':
			options_general['installed'] 	= False
			options_general['last_update'] 	= ''
		elif tool_installed == 'true':
			options_general['installed'] 	= True
			options_general['last_update'] 	= ''
		else:
			options_general['installed'] 	= True
			options_general['last_update'] 	= tool_installed

		return options_general


	def parseToolSpecificOptions(self, section, service_name, tooltype=ToolType.STANDARD):
		"""
		Parse the specific options inside a tool section in settings file.

		@Args		section: 		Section from config file corresponding to a tool
					service_name: 	Service targeted by the tool
					tooltype: 		ToolType
					
		@Returns	Dictionary options_specific
		"""
		# opt_specific is a dictionary: "option" => (type, value)
		options_specific    = dict()

		if service_name in SPECIFIC_TOOL_OPTIONS.keys():
			for option in SPECIFIC_TOOL_OPTIONS[service_name]:
				# Boolean options (default False)
				if SPECIFIC_TOOL_OPTIONS[service_name][option] == '':
					options_specific[option] = (bool, self.config_parsers[service_name].safeGetBoolean(section, option + '_specific', False))

				# List-type options
				else:
					value_list = [ e.lower() for e in self.config_parsers[service_name].safeGetList(section, option + '_specific', ',', []) ]
					if value_list:
						for e in value_list:
							if e.lower() not in self.general_settings[service_name][SPECIFIC_TOOL_OPTIONS[service_name][option]]:
								value_list.remove(e)
								self.output.printWarning('[{0}{1}] Section "{2}" > option "{3}" contains invalid entry ("{4}")'.format(service_name, CONF_EXT, section, option, e))
					options_specific[option] = (list, value_list)

		return options_specific


	def changeInstalledOption(self, service_name, tool_name, install_status):
		"""
		Change the install status for a given tool.
		Change is made into the INSTALL_STATUS_CONF_FILE

		@Args		service_name: 		service targeted by the tool
					tool_name: 			Tool name as it appears in config file
					install_status: 	Boolean
		@Returns	Boolean indicating operation status
		"""
		# If value == True: tool installed, put the current datetime
		if install_status:
			value = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		else:
			value = 'False'

		if not self.config_parsers[INSTALL_STATUS_CONF_FILE].safeSet(service_name, tool_name, value):
			raise Exception

		# If "MULTI_SERVICES" tool, change the install status of all the references
		if service_name == MULTI_SERVICES_CONF_FILE:
			for tool in self.toolbox.searchInToolboxToolsReferencing(tool_name):
				if not self.config_parsers[INSTALL_STATUS_CONF_FILE].safeSet(tool.service_name, tool.name, value):
					raise Exception

		return self.saveSettings(INSTALL_STATUS_CONF_FILE)


	def saveSettings(self, conf_filename):
		"""
		Save settings into config file.
		Make sure changes are thus taken into account.

		@Args		conf_filename: configuration filename (without extension)
		@Returns	Boolean indicating operation status
		"""
		try:
			config_file = FileUtils.concat_path(self.settings_dir, conf_filename + CONF_EXT)
			with open(config_file, 'w') as handle:
				self.config_parsers[conf_filename].write(handle)
				# Re-read to take change into account
				self.config_parsers[conf_filename].read(config_file) # warning: takes filename as param
			return True
		except:
			traceback.print_exc()
			return False		
