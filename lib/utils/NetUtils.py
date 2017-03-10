import socket
from IPy import IP


class NetUtils(object):

	@staticmethod
	def isValidIP(string):
		"""
		Check if given string represents a valid IP address 
		@Args	Input string
		@Return boolean
		"""
		try:
			IP(string)
			return True
		except:
			return False

	@staticmethod
	def isTcpPortOpen(ip, port):
		"""
		Check if given TCP port is open
		@Args 	ip: 	IP address
				port: 	Port number
		@Return boolean
		"""
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((ip, int(port)))
			s.shutdown(2)
			return True
		except:
			return False


	@staticmethod
	def isUdpPortOpen(ip, port):
		"""
		Check if given UDP port is open
		@Args 	ip: 	IP address
				port: 	Port number
		@Return boolean
		"""
		return True