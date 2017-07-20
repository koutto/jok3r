###
### Arguments parser
###
import sys
import time
import argparse
from urlparse import urlparse
from lib.core.Target import Target
from lib.core.SpecificOptions import SpecificOptions
from lib.core.Constants import *
from lib.utils.FileUtils import FileUtils

import textwrap as _textwrap

class LineWrapRawTextHelpFormatter(argparse.RawDescriptionHelpFormatter):
	def _split_lines(self, text, width):
		"""
		For custom max width
		"""
		text = self._whitespace_matcher.sub(' ', text).strip()
		return _textwrap.wrap(text, ARGPARSE_MAX_WIDTH)

	def _format_action_invocation(self, action):
		"""
		Custom for concatenation short and long option with only one occurrence of metavar
		"""
		if not action.option_strings:
			default = self._get_default_metavar_for_positional(action)
			metavar, = self._metavar_formatter(action, default)(1)
			return metavar
		else:
			parts = []

			# if the Optional doesn't take a value, format is:
			#    -s, --long
			if action.nargs == 0:
			    parts.extend(action.option_strings)

			# if the Optional takes a value, format is:
			#    -s ARGS, --long ARGS
			else:
				default = self._get_default_metavar_for_optional(action)
				args_string = self._format_args(action, default)
				for option_string in action.option_strings:
					parts.append(option_string)

				return '%s %s' % (', '.join(parts), args_string)

			return ', '.join(parts)

	def _get_default_metavar_for_optional(self, action):
		return action.dest.upper()

	def _get_default_metavar_for_positional(self, action):
		return action.dest.upper()



class ArgumentsParser(object):

	def __init__(self, settings, output):
		self.settings 		= settings
		self.output 		= output
		self.target 		= None
		self.specific 		= {}

		formatter_class=lambda prog: LineWrapRawTextHelpFormatter(prog, max_help_position=ARGPARSE_MAX_HELP_POSITION)
		self.parser 		= argparse.ArgumentParser(description=BANNER, formatter_class=formatter_class)
		self.contparsing	= True
		self.selected_tools_categories = []

		# Parse and check command line arguments, and add specific settings
		self.args = self.parseArguments()
		self.checkArgsSyntax()


	def parseArguments(self):
		"""
		Command-line arguments parser (using argparse)
		@Returns	None
		"""

		self.parser.add_argument('--version', action='version', version=CURRENT_VERSION)

		# Toolbox management
		toolbox = self.parser.add_argument_group('Toolbox management')
		toolbox.add_argument('--show-toolbox', help='Show toolbox content for a given service', 
						   action='store', dest='show_toolbox', type=str, metavar='<service>', default=None)
		toolbox.add_argument('--show-toolbox-brief', help='Show toolbox content for a given service (brief)', 
						   action='store', dest='show_toolbox_brief', type=str, metavar='<service>', default=None)
		toolbox.add_argument('--install-toolbox', help='Install tools for a given service that are not installed yet',
						   action='store', dest='install_toolbox', type=str, metavar='<service>', default=None)
		toolbox.add_argument('--install-all', help='Install all toolbox (for all services)',
						   action='store_true', dest='install_all', default=False)
		toolbox.add_argument('--update-toolbox', help='Try to update tools for a given service',
						   action='store', dest='update_toolbox', type=str, metavar='<service>', default=None)
		toolbox.add_argument('--update-all', help='Update every tool for all services',
						   action='store_true', dest='update_all', default=False)
		toolbox.add_argument('--uninstall-tool', help='Uninstall a given tool',
						   action='store', dest='uninstall_tool', type=str, metavar='<tool_name>', default=None)
		toolbox.add_argument('--uninstall-toolbox', help='Uninstall all tools into the toolbox for a given service',
						   action='store', dest='uninstall_toolbox', type=str, metavar='<service>', default=None)
		toolbox.add_argument('--uninstall-all', help='Uninstall the whole toolbox',
						   action='store_true', dest='uninstall_all', default=False)
		toolbox.add_argument('--list-services', help='List supported services', 
			 			   action='store_true', dest='list_services', default=False)
		toolbox.add_argument('--list-categories', help='List tools categories for a given service',
						   action='store', dest='list_categories', type=str, metavar='<service>', default=None)
		toolbox.add_argument('--fast', help='Do not prompt for confirmation before install and do not check install after',
						   action='store_true', dest='fast_install', default=False)

		# Target
		target = self.parser.add_argument_group('Target')
		target.add_argument('-u', '--url', help='Target URL', action='store', dest='url', metavar='<url>', type=str, default='')
		target.add_argument('--ip', help='Target IP', action='store', dest='ip', metavar='<ip>', type=str, default=None)
		target.add_argument('-p', '--port', help='Target Port', action='store', dest='port', metavar='<port>', type=int, default=None)
		target.add_argument('-s', '--service', help='Service (see --list-services)', 
			                action='store', dest='service', metavar='<service>', type=str, default=None)
		target.add_argument('--no-port-check', help='Do not check if port is actually open', 
							action='store_true', dest='no_port_check', default=False)

		# Tools categories
		tools_selection = self.parser.add_argument_group('Tools running')
		tools_selection.add_argument('--only', help='Run only tools in specified categories (default: all categories)', 
						 	action='store', dest='only', metavar='<categories>', type=str, default=None)
		tools_selection.add_argument('--exclude', help='Do not run tools in specified categories', 
						 	action='store', dest='exclude', metavar='<categories>', type=str, default=None)
		tools_selection.add_argument('--auto', help='Do not prompt before running tool, auto yes',
							action='store_true', dest='auto_yes', default=False)
		tools_selection.add_argument('--ignore-specific', help='Ignore context specific options',
							action='store_true', dest='ignore_specific', default=False)
		tools_selection.add_argument('--single', help='Run a single given tool',
							action='store', dest='single_tool', metavar='<tool_name>', type=str, default=None)

		# Output settings
		output = self.parser.add_argument_group('Output settings')
		output.add_argument('-o', '--output', help='Output directory where are stored all the results (default: generated dir in "{0}")'.format(DEFAULT_OUTPUT_DIR), 
							action='store', dest='output_dir', metavar='<directory>', type=str, required=False, default=None)


		# Specific
		specific = self.parser.add_argument_group('Context specific settings')
		specific.add_argument('--list-specific', help='List supported context specific settings for a given service',
							  action='store', dest='list_specific', metavar='<service>', type=str, default=None)
		specific.add_argument('specific', help='Context specific options, format name=value (value can be "all")', 
				              metavar='<specific_options>', nargs='*')

		args = self.parser.parse_args()

		return args


	def checkArgsSyntax(self):
		"""
		Check if arguments are correctly specified
		"""
		self.checkArgsToolboxManagement()
		self.checkArgsTarget()
		self.checkArgsToolsSelection()
		self.checkArgsOutput()
		self.checkArgsSpecificOptions()


	def checkArgsToolboxManagement(self):
		"""
		Check arguments related to Toolbox management
		"""
		if self.args.install_toolbox and self.args.update_toolbox:
			self.output.printError('Choose either --install-toolbox or --update-toolbox')
			sys.exit(0)

		if self.args.uninstall_tool:
			if not self.settings.toolbox.searchInToolbox(self.args.uninstall_tool):
				self.output.printError('Tool "{0}" does not exist into toolbox, check name.'.format(self.args.uninstall_tool))
				sys.exit(0)
			self.contparsing = False
			return

		if self.args.uninstall_toolbox:
			self.args.uninstall_toolbox = self.args.uninstall_toolbox.strip().lower()
			if self.args.uninstall_toolbox not in self.settings.general_settings.keys():
				self.output.printError('Cannot uninstall toolbox. Service is not supported')
				sys.exit(0)
			self.contparsing = False
			return

		if self.args.show_toolbox:
			self.args.show_toolbox = self.args.show_toolbox.strip().lower()
			if self.args.show_toolbox not in self.settings.general_settings.keys():
				self.output.printError('Cannot show toolbox. Service is not supported')
				sys.exit(0)
			self.contparsing = False
			return

		if self.args.show_toolbox_brief:
			self.args.show_toolbox_brief = self.args.show_toolbox_brief.strip().lower()
			if self.args.show_toolbox_brief not in self.settings.general_settings.keys():
				self.output.printError('Cannot show toolbox. Service is not supported')
				sys.exit(0)
			self.contparsing = False
			return

		if self.args.install_toolbox:
			self.args.install_toolbox = self.args.install_toolbox.strip().lower()
			if self.args.install_toolbox not in self.settings.general_settings.keys():
				self.output.printError('Cannot install toolbox. Service is not supported')
				sys.exit(0)
			self.contparsing = False
			return

		if self.args.update_toolbox:
			self.args.update_toolbox = self.args.update_toolbox.strip().lower()
			if self.args.update_toolbox not in self.settings.general_settings.keys():
				self.output.printError('Cannot update toolbox. Service is not supported')
				sys.exit(0)
			self.contparsing = False
			return

		if self.args.list_categories:
			self.args.list_categories = self.args.list_categories.strip().lower()
			if self.args.list_categories not in self.settings.general_settings.keys():
				self.output.printError('Cannot list tool categories. Service is not supported')
				sys.exit(0)
			self.contparsing = False
			return

		if self.args.list_services 	or \
		   self.args.install_all 	or \
		   self.args.uninstall_all 	or \
		   self.args.update_all:
			self.contparsing = False
			return


	def checkArgsTarget(self):
		"""
		Check arguments related to Target
		"""
		if not self.contparsing or self.args.list_specific:
			return

		if self.args.url and self.args.ip:
			self.output.printError('Both URL and IP cannot be given')
			sys.exit(0)

		if not self.args.url and not self.args.ip:
			self.output.printError('Target is not specified')
			sys.exit(0)

		if self.args.ip:
			if not self.args.port:
				self.output.printError('Port must be specified')
				sys.exit(0)
			self.args.port = int(self.args.port)
			if self.args.port < 0 or self.args.port > 65535:
				self.output.printError('Target port is not valid [0-65535]')
				sys.exit(0)

		if self.args.url:
			if self.args.service and self.args.service != 'http':
				self.output.printWarning('URL only supported for HTTP service. Automatically switch to HTTP')
			self.args.service = 'http'
		elif not self.args.service:
			self.output.printError('Target service must be specified')
			sys.exit(0)

		self.args.service = self.args.service.strip().lower()
		if self.args.service not in self.settings.general_settings.keys():
			self.output.printError('Service is not supported')
			sys.exit(0)
		if self.args.url and self.args.service != 'http':
			self.output.printError('URL specified but service is not HTTP')
			sys.exit(0)
		#self.selected_tools_categories = self.settings.general_settings[self.args.service]['tools_categories']

		# self.args.protocol = self.args.protocol.strip().lower()
		# if self.args.protocol not in ('tcp', 'udp'):
		# 	self.output.printError('Protocol must be either tcp or udp')
		# 	sys.exit(0)
		self.checkAndInitializeTarget(self.args.ip, self.args.port, self.args.service, self.args.url, self.args.no_port_check)


	def checkArgsToolsSelection(self):
		"""
		Check arguments related to Tools selection
		"""
		if not self.contparsing or self.args.list_specific:
			return

		if self.args.single_tool:
			self.args.single_tool = self.args.single_tool.strip().lower()
			found_tool = self.settings.toolbox.searchInToolboxForService(self.args.single_tool, self.args.service)
			if not found_tool:
				self.output.printError('Supplied tool is not in toolbox for service {0}, check correct name'.format(self.args.service))
				sys.exit(0)
			return

		if self.args.only and self.args.exclude:
			self.output.printError('--only and --exclude cannot be used at the same time')
			sys.exit(0)

		if self.args.only:
			self.args.only = [ e.strip().lower() for e in self.args.only.split(',') ]
			for cat in self.args.only:
				if cat not in self.settings.general_settings[self.args.service]['tools_categories']:
					self.output.printError('Error with --only: category named "{0}" does not exist for selected service'.format(cat))
					self.settings.toolbox.printListCategories(self.output, self.args.service)
					sys.exit(0)

		if self.args.exclude:
			self.args.exclude = [ e.strip().lower() for e in self.args.exclude.split(',') ]
			for cat in self.args.exclude:
				if cat not in self.settings.general_settings[self.args.service]['tools_categories']:
					self.output.printError('Error with --exclude: category named "{0}" does not exist for selected service'.format(cat))
					self.settings.toolbox.printListCategories(self.output, self.args.service)
					sys.exit(0)

		self.checkSelectedToolsCategories(self.args.service, self.args.only, self.args.exclude)


	def checkArgsOutput(self):
		"""
		Check arguments related to Output
		"""
		if not self.contparsing or self.args.list_specific:
			return

		if self.args.output_dir:
			self.args.output_dir = self.args.output_dir.strip()
		else:
			self.args.output_dir = self.defineOutputDir(self.args.output_dir, self.target.host, self.target.port, 
														self.target.protocol, self.target.service)

		if FileUtils.is_dir(self.args.output_dir):
			self.output.printError('Directory "{0}" already exists. Choose another name.'.format(self.args.output_dir))
			sys.exit(0)
		if not FileUtils.create_directory(self.args.output_dir):
			self.output.printError('Impossible to create output directory "{0}". Check permissions'.format(self.args.output_dir))
			sys.exit(0)


	def checkArgsSpecificOptions(self):
		"""
		Check arguments related to Specific options
		"""
		if not self.contparsing:
			return

		if self.args.list_specific:
			self.args.list_specific = self.args.list_specific.strip().lower()
			if self.args.list_specific not in self.settings.general_settings.keys():
				self.output.printError('Cannot list context specific options. Service is not supported')
				sys.exit(0)
			return

		for setting in self.args.specific:
			name 	= setting.split('=')[0].strip().lower()
			value 	= setting.split('=')[1].strip().lower()
			if name not in SPECIFIC_TOOL_OPTIONS[self.args.service]:
				self.output.printError('Specific option "{0}" does not exist for service {1}'.format(name, self.args.service))
				SpecificOptions.listAvailableSpecificOptions(self.settings, self.args.service, self.output)
				sys.exit(0)

			option_type = SpecificOptions.specificOptionType(self.args.service, name)
			if option_type == 'boolean':
				if value == 'true':
					self.specific[name] = True
				elif value == 'false':
					self.specific[name] = False
				else:
					self.output.printError('Specific option "{0}" is boolean type. Only accepts true/false as value'.format(name))
					sys.exit(0)

			elif option_type == 'list_member':
				if SpecificOptions.isMemberOfList(self.settings, self.args.service, name, value) or value == 'all':
					self.specific[name] = value
				else:
					self.output.printError('Specific option "{0}" is list member type. Only member of the list is supported or "all"'.format(name))
					print
					SpecificOptions.listAvailableSpecificOptions(self.settings, self.args.service, self.output)
					sys.exit(0)		

		# Autodetect https and set ssl tag	
		if self.args.url:
			if self.args.url.lower().startswith('https://'):
				if 'ssl' not in self.specific.keys():
					self.specific['ssl'] = True


	def checkAndInitializeTarget(self, ip, port, service, url, no_port_check):
		"""
		Initialize the target based either on IP:PORT or on URL, plus service
		@Args 		ip: 			IP address (None if url given)
					port: 			Port number (None if url given)
					service:		Service name
					url:			URL (None if ip+port given)
					no_port_check: 	If True, no check for open port
		@Returns 	Boolean indicating status
		"""
		self.target = Target(ip, port, service, url, no_port_check=no_port_check)
		if not self.target.is_reachable:
			self.output.printError('Target seems not to be reachable...')
			sys.exit(0)


	def printSummary(self, output):
		"""
		Print a summary of passed arguments
		@Args 	 	output:		CLIOutput instance
		@Returns 	None
		"""
		# Output directory
		output.printNewLine('   Output directory : {0}'.format(self.args.output_dir))
		print
		
		if not self.args.single_tool:
			# Selected tools categories
			output.printNewLine('   Selected categories : {0}'.format('All' if \
				len(self.selected_tools_categories) == len(self.settings.general_settings[self.args.service]['tools_categories']) else ''))
			for cat in self.selected_tools_categories:
				output.printNewLine('     +-- {0}'.format(cat))
			print

			# Specific options
			output.printNewLine('   Specific options : {0}'.format('None' if not self.specific else ''))
			for setting in self.specific.keys():
				output.printNewLine('     +-- {0}\t\t: {1}'.format(setting, str(self.specific[setting])))
			print


	def checkSelectedToolsCategories(self, service_name, list_only, list_exclude):
		"""
		Compute list of selected tools categories that must be run against the target
		@Args 		service_name:	target service name
					list_only: 		list of selected categories
					list_exclude:	list of categories to exclude
		@Returns	Boolean
		"""
		if list_only and list_exclude:
			return False
		if list_only:
			self.selected_tools_categories = list_only
		elif list_exclude:
			self.selected_tools_categories = list(set(self.settings.general_settings[service_name]['tools_categories']).difference(set(list_exclude)))
		# Else, no particular selection
		else:
			self.selected_tools_categories = self.settings.general_settings[service_name]['tools_categories']
		return True


	def defineOutputDir(self, output_dir, host, port, protocol, service):
		"""
		Define the output directory name for storing results
		@Args 		output_dir:		name coming from argument (if defined by user)
					host:			target host name
					port:			target port number
					protocol:		protocol tcp or udp
					service: 		
		@Returns 	the final name to use as directory name
		"""
		if output_dir:
			return output_dir
		return FileUtils.concat_path(DEFAULT_OUTPUT_DIR, \
			'{0}-{1}{2}_{3}_{4}'.format(host, port, protocol, service, str(time.time()).split('.')[0]))

