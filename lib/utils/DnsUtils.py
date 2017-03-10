
import socket


class DnsUtils(object):

	@staticmethod
	def dnsLookup(host):
		ips = []
		try:
			ips = list(set(str(i[4][0]) for i in socket.getaddrinfo(host, 80)))
		except Exception as e:
			pass
		return ips