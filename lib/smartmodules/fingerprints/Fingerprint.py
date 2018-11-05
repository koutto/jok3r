# -*- coding: utf-8 -*-
###
### SmartModules > Fingerprints > Fingerprint
###
import re

VERSION_REGEXP = '(?P<version>[0-9.]+)?'

class Fingerprint:

	def __init__(self, fingerprints):
		self.fingerprints = fingerprints


	def search(self, text):
		"""
		"""
		result = ''
		for pattern in self.fingerprints:
			pattern = pattern.replace('[VERSION]', VERSION_REGEXP)
			m = re.search(pattern, text, re.IGNORECASE)
			if m:
				result = self.fingerprints[pattern]
				# If version is present, add it as suffix
				if m.group('version'):
					result += '|{}'.format(m.group('version'))
				break
		return result

