###
### Command builder
###
import re
import regex
from lib.utils.FileUtils import FileUtils
from lib.core.Constants import *
from lib.core.SpecificOptions import SpecificOptions

# ---------------------------
# Tags supported in commands:
# ---------------------------
# [IP]			Target IP
# [URL]			Target URL
# [HOST]		Target host
# [PORT]		Target port
# [PROTOCOL]	Protocol tcp/udp
# [SERVICE]		Service name
# [OUTPUT]		Output file
# [OUTPUTDIR] 	Output directory (when tool save results in a directory, e.g. skipfish)
# [TOOLBOXDIR]	Toolbox directory
#
# + specific tags depending on each service, eg. for http:
# [SSL option="value"]					In case SSL should be used, add the specified option. e.g.: [SSL option="--ssl"]
# [CMS cms1="val" cms2="val" ...] 		Option specific to CMS. e.g.: [CMS drupal="--type Drupal" joomla="--type Joomla"]
# [TECHNO techno1="val" techno2="val"]	Option specific to technology. e.g.: [TECHNO php="-l php" asp="-l asp"]
# [SERVER server1="val" server2="val"]	Option specific to server. e.g.: [SERVER apache="--serv apache" tomcat="--serv tomcat"]

class Command(object):

	def __init__(self, 
				 directory, 
				 raw_cmdline, 
				 target, 
				 toolbox_dir, 
				 output_file, 
				 output_dir,
				 service_name,
				 specific_args):
	
		self.directory	 	= FileUtils.absolute_path(directory)	# directory where the command should be launched
		self.cmdline 	 	= raw_cmdline
		self.target 	 	= target
		self.toolbox_dir 	= FileUtils.absolute_path(toolbox_dir)
		self.output_file 	= output_file
		self.output_dir  	= output_dir
		self.service 	 	= service_name
		self.specific_args 	= specific_args

	def getParsedRunCommandLine(self):
		"""
		Replace tags in a command aimed at running a tool.
		Return the parsed command line, ready to be executed
		"""
		if not self.target or not self.output_file:
			return None

		self.replaceIP()
		self.replaceURL()
		self.replaceHOST()
		self.replacePORT()
		self.replacePROTOCOL()
		self.replaceSERVICE()
		self.replaceOUTPUT()
		self.replaceOUTPUTDIR()
		self.replaceTOOLBOXDIR()
		self.replaceSpecificTags()

		self.cmdline = 'cd {0}; '.format(self.directory) + self.cmdline
		return self.cmdline


	def getParsedInstallCommandLine(self):
		"""
		Replace tags in a command aimed at installing a tool.
		Prefix with cd [tool_dir] to make sure commands will be run in correct context
		Return the parsed command line, ready to be executed
		"""
		self.replaceTOOLBOXDIR()
		self.cmdline = 'cd {0}; '.format(self.directory) + self.cmdline
		return self.cmdline


	def getStandardCommandLine(self):
		"""
		Return a standard command line (without tag)
		"""
		self.cmdline = 'cd {0}; '.format(self.directory) + self.cmdline
		return self.cmdline


	def replaceURL(self):
		"""
		Replace [URL]
		"""
		pattern = re.compile('\[URL\]', re.IGNORECASE)
		self.cmdline = pattern.sub(self.target.url, self.cmdline)


	def replaceHOST(self):
		"""
		Replace [HOST]
		"""
		pattern = re.compile('\[HOST\]', re.IGNORECASE)
		self.cmdline = pattern.sub(self.target.host, self.cmdline)


	def replaceIP(self):
		"""
		Replace [IP]
		"""
		pattern = re.compile('\[IP\]', re.IGNORECASE)
		self.cmdline = pattern.sub(self.target.ip, self.cmdline)


	def replacePORT(self):
		"""
		Replace [PORT]
		"""
		pattern = re.compile('\[PORT\]', re.IGNORECASE)
		self.cmdline = pattern.sub(self.target.port, self.cmdline)


	def replacePROTOCOL(self):
		"""
		Replace [PROTOCOL]
		"""
		pattern = re.compile('\[PROTOCOL\]', re.IGNORECASE)
		self.cmdline = pattern.sub(self.target.protocol, self.cmdline)


	def replaceSERVICE(self):
		"""
		Replace [SERVICE]
		"""
		pattern = re.compile('\[SERVICE\]', re.IGNORECASE)
		self.cmdline = pattern.sub(self.target.port, self.cmdline)		


	def replaceOUTPUT(self):
		"""
		Replace [OUTPUT] if present
		Else, add at the end of the command: 2>&1 | tee [OUTPUT]
		"""
		pattern = re.compile('\[OUTPUT\]', re.IGNORECASE)
		if pattern.search(self.cmdline):
			self.cmdline = pattern.sub('"{0}"'.format(self.output_file), self.cmdline)
		else:
			self.cmdline += ' 2>&1 | tee "{0}"'.format(self.output_file)


	def replaceOUTPUTDIR(self):
		"""
		Replace [OUTPUTDIR] if present
		"""
		pattern = re.compile('\[OUTPUTDIR\]', re.IGNORECASE)
		self.cmdline = pattern.sub(self.output_dir, self.cmdline)		


	def replaceTOOLBOXDIR(self):
		"""
		Replace [TOOLBOXDIR] (toolbox directory)
		"""
		pattern = re.compile('\[TOOLBOXDIR\]', re.IGNORECASE)
		self.cmdline = pattern.sub(self.toolbox_dir, self.cmdline)


	def replaceSpecificTags(self):
		"""
		Replace specific tags (depends on the selected service) 
		eg. for http :
		[SSL option="value"]
		[CMS cms1="val" cms2="val" ... default="val"]
		"""
		if not self.specific_args:
			return
			
		for tag in SPECIFIC_TOOL_OPTIONS[self.service].keys():
			option_type = SpecificOptions.specificOptionType(self.service, tag)

			if option_type == 'boolean':
				try:
					pattern = re.compile(r'\[' + tag.upper() + '\s+option\s*=\s*[\'"](?P<option>.*?)[\'"]\s*\]', re.IGNORECASE)
					m = pattern.search(self.cmdline)
					# option is True
					if tag in self.specific_args.keys() and self.specific_args[tag]:
						self.cmdline = pattern.sub(m.group('option'), self.cmdline)
					# option is False
					else:
						self.cmdline = pattern.sub('', self.cmdline)
				except Exception as e:
					pass	

			elif option_type == 'list_member':	
				try:
					pattern = regex.compile(r'\[' + tag.upper() + '(?:\s+(?P<name>\w+)\s*=\s*[\'"](?P<value>\w*)[\'"])+\s*\]', regex.IGNORECASE)
					m = pattern.search(self.cmdline)
					capt = m.capturesdict()
					if tag in self.specific_args.keys() and self.specific_args[tag]:
						value = capt['value'][capt['name'].index(self.specific_args[tag])]
						self.cmdline = pattern.sub(value, self.cmdline)
					elif 'default' in [e.lower() for e in capt['name']]:
						value = capt['value'][capt['name'].index('default')]
						self.cmdline = pattern.sub(value, self.cmdline)
					else:
						self.cmdline = pattern.sub('', self.cmdline)
				except Exception as e:
					#print e
					pass