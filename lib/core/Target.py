###
### Target 
###
import textwrap
from urlparse import urlparse
from lib.utils.WebUtils import WebUtils
from lib.utils.NetUtils import NetUtils
from lib.utils.DnsUtils import DnsUtils
from lib.core.Constants import *


class Target(object):

	def __init__(self, ip, port, service, url):
		"""
		Initialize Target. 
		@Args 	ip: 		IP address
				port: 		TCP/UDP port
				service:	service name
				url:		URL address (can be empty if ip+port)
		"""

		self.ip 			= ip
		self.port 			= port
		self.service 		= service
		self.url 			= url
		self.host 			= None
		self.protocol 		= PROTOCOL[self.service] if self.service in PROTOCOL else 'tcp'
		self.is_reachable 	= False

		# Specific HTTP/HTTPS
		self.proto 			= ''
		self.status 		= None
		self.resp_headers 	= None

		if self.url:
			self.initWithURL()

		elif self.ip and self.port:
			self.initWithIP()
	

	def initWithURL(self):
		"""
		Initialize the target with an URL (for web app as target)
		@Returns 	boolean
		"""
		# Add http:// if necessary
		self.url = WebUtils.addProtocolHttp(self.url)
		parsed = urlparse(self.url)

		# Parse url
		self.proto = 'HTTPS' if parsed.scheme == 'https' else 'HTTP'
		self.host = parsed.netloc
		if ':' in self.host:
			self.host = self.host[:self.host.rfind(':')]
		
		if parsed.port:
			self.port = str(parsed.port)
		else:
			self.port = '443' if self.proto == 'HTTPS' else '80'

		# Check if url is reachable and retrieve headers
		self.is_reachable, self.status, self.resp_headers = WebUtils.checkUrlExists(self.url)
		if not self.is_reachable:
			return False

		# DNS lookup to get IP corresponding to host (if several, just take the first one)
		self.ip = DnsUtils.dnsLookup(self.host)[0]
		return True


	def initWithIP(self):
		"""
		Initialize the target with an IP:PORT
		@Returns 	boolean
		"""
		# Check port
		if self.port < 0 or self.port > 65535:
			return False

		# Case where ip is actually a hostname
		if not NetUtils.isValidIP(self.ip):
			self.host = self.ip	
			# DNS lookup to get IP corresponding to host (if several, just take the first one)
			ips = DnsUtils.dnsLookup(self.host)
			if not ips:
				return False
			self.ip = ips[0]

		# Check if IP:PORT is reachable
		if self.protocol == 'tcp':
			if not NetUtils.isTcpPortOpen(self.ip, self.port):
				self.is_reachable = False
				return False
		else:
			if not NetUtils.isUdpPortOpen(self.ip, self.port):
				self.is_reachable = False
				return False
		self.is_reachable = True
		return True


	def printSummary(self, output):
		"""
		Print summary about target
		@Args 		output: 	CLIOutput instance
		@Returns 	None
		"""
		if self.service == 'http':
			output.printNewLine('   URL          : {0}'.format(self.url))
			output.printNewLine('   Protocol     : {0}'.format(self.proto))
			output.printNewLine('   Host         : {0}'.format(self.host))
			output.printNewLine('   IP Address   : {0}'.format(self.ip))
			output.printNewLine('   Port         : {0}/tcp'.format(self.port))
			output.printNewLine('   HTTP Status  : {0}'.format(self.status))
			output.printNewLine('   Resp Headers :')
			for h in self.resp_headers.keys():
				output.printRaw('     +-- {0}: '.format(h))
				firstline = True
				for l in textwrap.wrap(self.resp_headers[h], 160):
					output.printRaw('{0}{1}\n'.format('' if firstline else ' '*5+'|'+' '*3, l))
					firstline = False
			#output.printNewLine('   HTTP code : {0}'.format(str(self.httpcode) if self.httpcode != -1 else 'N/A'))
			print

		else:
			output.printNewLine('   IP           : {0}'.format(self.ip))
			output.printNewLine('   Host         : {0}'.format(self.host))
			output.printNewLine('   Port         : {0}/{1}'.format(self.port, self.protocol))
			output.printNewLine('   Service      : {0}'.format(self.service))
			print




