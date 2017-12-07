
import re
import urllib3
import httplib

urllib3.disable_warnings()

HTTP_KEYWORDS = 'html|http|head|body|404|403|401|500'

class WebUtils(object):

	@staticmethod
	def addProtocolHttp(url):
		"""
		If protocol not present, add http:// at the beginning
		@Args 	url to edit
		@Return str url with http:// prefix
		"""
		if not url:
			return False
		if not url.startswith('http://') and not url.startswith('https://'):
			return 'http://{0}'.format(url)
		return url

	@staticmethod
	def isValidUrl(url):
		"""
		Check if given URL is valid 
		@Args	url to test
		@Return boolean
		"""
		regex = re.compile(
			r'^https?://'  # http:// or https://
			r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
			r'localhost|'  # localhost...
			r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
			r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
			r'(?::\d+)?'  # optional port
			r'(?:/?|[/?]\S+)$', re.IGNORECASE)
		return True if regex.match(url) else False

	@staticmethod
	def checkUrlExists(url):
		"""
		Check if an URL is reachable.
		@Args 	url to check
		@Return tupple (Boolean, HTTP code status, HTTP response headers)
		"""
		try:
			http = urllib3.PoolManager(cert_reqs='CERT_NONE')
			r = http.request('GET', url)
			return (True, r.status, r.getheaders())
		except Exception as e:
			return (False, None, None)

	@staticmethod
	def checkIfHttpData(ip, port):
		"""
		Check if the given ip:port actually returns HTTP data
		"""
		timeout = urllib3.util.timeout.Timeout(0.1)
		http_url  = 'http://{0}:{1}'.format(ip, port)
		https_url = 'https://{0}:{1}'.format(ip, port)
		regex = re.compile(HTTP_KEYWORDS, re.IGNORECASE)
		http = urllib3.PoolManager(cert_reqs='CERT_NONE')
		try:
			r1 = http.request('GET', https_url, timeout=timeout)
			r2 = http.request('GET', '{0}/aaa'.format(https_url), timeout=timeout)
			if r1.data or r2.data:
				if regex.search(r1.data) or regex.search(r2.data):
					return https_url
		except Exception as e:
			pass
		try:
			r1 = http.request('GET', http_url, timeout=timeout)
			r2 = http.request('GET', '{0}/aaa'.format(http_url), timeout=timeout)
			if r1.data or r2.data:
				if regex.search(r1.data) or regex.search(r2.data):
					return http_url
			return False
		except Exception as e:
			#print e
			return False



