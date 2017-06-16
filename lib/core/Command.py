###
### Core > Command
###
# ---------------------------
# Tags supported in commands:
# ---------------------------
# [IP]			 Target IP
# [URL]			 Target URL
# [HOST]		 Target host
# [PORT]		 Target port
# [PROTOCOL]	 Protocol tcp/udp
# [SERVICE]		 Service name
# [OUTPUT]		 Output file
# [OUTPUTDIR] 	 Output directory (when tool save results in a directory, e.g. skipfish)
# [TOOLBOXDIR]	 Toolbox directory
# [WORDLISTSDIR] Wordlists directory
#
# + specific tags depending on each service, eg. for http:
# [SSL option="value"]					In case SSL should be used, add the specified option. e.g.: [SSL option="--ssl"]
# [CMS cms1="val" cms2="val" ...] 		Option specific to CMS. e.g.: [CMS drupal="--type Drupal" joomla="--type Joomla"]
# [TECHNO techno1="val" techno2="val"]	Option specific to technology. e.g.: [TECHNO php="-l php" asp="-l asp"]
# [SERVER server1="val" server2="val"]	Option specific to server. e.g.: [SERVER apache="--serv apache" tomcat="--serv tomcat"]
#
import re
import regex
from lib.utils.FileUtils import FileUtils
from lib.utils.CmdUtils import CmdUtils
from lib.core.SpecificOptions import SpecificOptions
import Constants



class CommandType(object):
	RUN 	= 1
	INSTALL	= 2
	UPDATE	= 3


class Command(object):

	def __init__(self, 
				 cmdtype,
				 cmdline,
				 current_dir, 
				 toolbox_dir):
		"""
		Initilialize Command object 
		From a raw command line and information used to replace tags correctly

		@Args 	cmdtype:		Command type	
				cmdline:		Raw command-line (may contain tags)
				current_dir:	Directory where the command should be started
				toolbox_dir:	Toolbox directory

		"""
		self.cmdtype 			= cmdtype
		self.cmdline 			= cmdline # Keep the original command line
		self.current_dir		= FileUtils.absolute_path(current_dir)
		self.toolbox_dir		= FileUtils.absolute_path(toolbox_dir)
		self.parsed_cmdline		= ''


	def getParsedCmdline(self, 
						 output_dir=None,
				 		 output_filename=None,
				 		 target=None,
				 		 specific_args=None,
				 		 remove_args=False):
		"""
		Return the parsed command line, i.e. with the tags replaced by their correct values
		according to the context

		@Args 		output_dir:			Directory where outputs are saved (for RUN commands)
					output_filename:	Filename for output (for RUN commands)
					target: 			Target object (for RUN commands)
					specific_args: 		Specific arguments (for RUN commands)
					remove_args:		Boolean indicating if arguments from cmd must be deleted (for RUN commands)
										Used for check install commands

		@Returns 	Tuple	(full parsed cmdline, shortened parsed cmdline)
		"""

		self.parsed_cmdline = self.cmdline
		if self.cmdtype == CommandType.RUN:
			if remove_args:
				self.parsed_cmdline = CmdUtils.removeArgsFromCmd(self.parsed_cmdline)
			else:
				if not output_dir or not output_filename or not target:
					raise ValueError('Missing required arguments')

				output_dir 		= FileUtils.absolute_path(output_dir)
				output_file 	= FileUtils.concat_path(output_dir, output_filename)
				output_subdir 	= FileUtils.concat_path(output_dir, FileUtils.remove_ext(output_filename))

				self.replaceIP(target.ip)
				self.replaceURL(target.url)
				self.replaceHOST(target.host)
				self.replacePORT(target.port)
				self.replacePROTOCOL(target.protocol)
				self.replaceSERVICE(target.service)
				self.replaceOUTPUT(output_file)
				self.replaceOUTPUTDIR(output_subdir)
				self.replaceTOOLBOXDIR(self.toolbox_dir)
				self.replaceWORDLISTSDIR(Constants.WORDLISTS_DIR)
				self.replaceSpecificTags(target.service, specific_args)

		elif self.cmdtype in (CommandType.INSTALL, CommandType.UPDATE):
			self.replaceTOOLBOXDIR(self.toolbox_dir)

		else:
			raise ValueError('Invalid command type')

		# Shortened parsed command line:
		# 	- without "cd [...]" prefix
		# 	- without "2>&1 | tee [...]" suffix
		short_cmdline = self.parsed_cmdline
		endcmd_index = short_cmdline.rfind('2>&1 | tee')
		if endcmd_index > 0:
			short_cmdline = short_cmdline[:endcmd_index].strip()

		# Full parsed command line:	
		self.parsed_cmdline = 'cd {0}; '.format(self.current_dir) + self.parsed_cmdline

		return self.parsed_cmdline, short_cmdline


	def getSimplifiedRunCmd(self, fullcmd):
		"""
		Get simplified command, ie. without:
			- "cd [...];" prefix 
			- "2>&1 | tee [...]" suffix if present

		@Args 		fullcmd: 	The full command-line
		@Returns 	The simplified command line
		"""
		try:
			cmd = fullcmd[fullcmd.index(';')+1:].strip()

		except:
			return ''
		return cmd

	def replaceURL(self, url):
		"""
		Replace [URL]
		"""
		pattern = re.compile('\[URL\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(url, self.parsed_cmdline)


	def replaceHOST(self, host):
		"""
		Replace [HOST]
		"""
		pattern = re.compile('\[HOST\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(host, self.parsed_cmdline)


	def replaceIP(self, ip):
		"""
		Replace [IP]
		"""
		pattern = re.compile('\[IP\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(ip, self.parsed_cmdline)


	def replacePORT(self, port):
		"""
		Replace [PORT]
		"""
		pattern = re.compile('\[PORT\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(str(port), self.parsed_cmdline)


	def replacePROTOCOL(self, protocol):
		"""
		Replace [PROTOCOL]
		"""
		pattern = re.compile('\[PROTOCOL\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(protocol, self.parsed_cmdline)


	def replaceSERVICE(self, service):
		"""
		Replace [SERVICE]
		"""
		pattern = re.compile('\[SERVICE\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(service, self.parsed_cmdline)		


	def replaceOUTPUT(self, output_file):
		"""
		Replace [OUTPUT] if present
		Otherwise, add at the end of the command: 2>&1 | tee [OUTPUT]
		"""
		pattern = re.compile('\[OUTPUT\]', re.IGNORECASE)
		if pattern.search(self.parsed_cmdline):
			self.parsed_cmdline = pattern.sub('"{0}"'.format(output_file), self.parsed_cmdline)
		else:
			self.parsed_cmdline += ' 2>&1 | tee "{0}"'.format(output_file)


	def replaceOUTPUTDIR(self, output_dir):
		"""
		Replace [OUTPUTDIR] if present
		"""
		pattern = re.compile('\[OUTPUTDIR\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(output_dir, self.parsed_cmdline)		


	def replaceTOOLBOXDIR(self, toolbox_dir):
		"""
		Replace [TOOLBOXDIR] (toolbox directory)
		"""
		pattern = re.compile('\[TOOLBOXDIR\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(toolbox_dir, self.parsed_cmdline)


	def replaceWORDLISTSDIR(self, wordlists_dir):
		"""
		Replace [WORDLISTSDIR] (wordlists directory)
		"""
		pattern = re.compile('\[WORDLISTSDIR\]', re.IGNORECASE)
		self.parsed_cmdline = pattern.sub(wordlists_dir, self.parsed_cmdline)


	def replaceSpecificTags(self, service, specific_args):
		"""
		Replace specific tags (depends on the selected service) 
		eg. for http :
		[SSL option="value"]
		[CMS cms1="val" cms2="val" ... default="val"]
		"""
		for tag in Constants.SPECIFIC_TOOL_OPTIONS[service].keys():
			option_type = SpecificOptions.specificOptionType(service, tag)

			if option_type == 'boolean':
				try:
					pattern = re.compile(r'\[' + tag.upper() + '\s+option\s*=\s*[\'"](?P<option>.*?)[\'"]\s*\]', re.IGNORECASE)
					m = pattern.search(self.parsed_cmdline)
					# option is True
					if tag in specific_args.keys() and specific_args[tag]:
						self.parsed_cmdline = pattern.sub(m.group('option'), self.parsed_cmdline)
					# option is False
					else:
						self.parsed_cmdline = pattern.sub('', self.parsed_cmdline)
				except Exception as e:
					pass	

			elif option_type == 'list_member':	
				try:
					print tag
					print specific_args
					pattern = regex.compile(r'\[' + tag.upper() + '(?:\s+(?P<name>\w+)\s*=\s*[\'"](?P<value>[ a-zA-Z0-9_,;:-]*)[\'"])+\s*\]', regex.IGNORECASE)
					m = pattern.search(self.parsed_cmdline)
					capt = m.capturesdict()
					print capt
					if tag in specific_args.keys() and specific_args[tag]:
						value = capt['value'][capt['name'].index(specific_args[tag])]
						self.parsed_cmdline = pattern.sub(value, self.parsed_cmdline)
					elif 'default' in [e.lower() for e in capt['name']]:
						value = capt['value'][capt['name'].index('default')]
						self.parsed_cmdline = pattern.sub(value, self.parsed_cmdline)
					else:
						self.parsed_cmdline = pattern.sub('', self.parsed_cmdline)
				except Exception as e:
					pass