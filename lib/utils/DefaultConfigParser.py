# -*- coding: utf-8 -*-
###
### Utils > DefaultConfigParser
###
import configparser
import traceback
import ast


class DefaultConfigParser(configparser.ConfigParser):
	"""
	ConfigParser subclass used for safe configuration file parsing 
	"""

	def __init__(self):
		configparser.ConfigParser.__init__(self, allow_no_value=True)


	def safe_get(self, section, option, default, allowed=None):
		"""
		Get a string with exception handling
		"""
		try:
			result = configparser.ConfigParser.get(self, section, option)
			if allowed is not None:
				return result if result in allowed else default
			else:
				return result
		except (configparser.NoSectionError, configparser.NoOptionError):
			return default


	def safe_get_lower(self, section, option, default, allowed=None):
		"""
		Get a string in lowercase with exception handling
		"""
		try:
			result = configparser.ConfigParser.get(self, section, option)
			if result:
				result = result.lower()
			if allowed is not None:
				return result if result in allowed else default
			else:
				return result
		except (configparser.NoSectionError, configparser.NoOptionError):
			return default


	def safe_get_float(self, section, option, default, allowed=None):
		"""
		Get a float with exception handling
		"""
		try:
			result = configparser.ConfigParser.getfloat(self, section, option)
			if allowed is not None:
				return result if result in allowed else default
			else:
				return result
		except (configparser.NoSectionError, configparser.NoOptionError):
			return default


	def safe_get_boolean(self, section, option, default):
		"""
		Get a boolean with exception handling
		"""
		try:
			result = configparser.ConfigParser.getboolean(self, section, option)
			return result if isinstance(result, bool) else default
		except (configparser.NoSectionError, configparser.NoOptionError):
			return default


	def safe_get_int(self, section, option, default, allowed=None):
		"""
		Get an integer with exception handling
		"""
		try:
			result = configparser.ConfigParser.getint(self, section, option)
			if allowed is not None:
				return result if result in allowed else default
			else:
				return result
		except (configparser.NoSectionError, configparser.NoOptionError):
			return default


	def safe_get_list(self, section, option, sep=',', default=None):
		"""
		Get a list with exception handling
		"""
		try:
			result_str = self.safe_get(section, option, None, None)
			if result_str is not None:
				return [ e.strip() for e in result_str.split(sep) ]
			else:
				return default
		except:
			return default


	def safe_get_multi(self, section, option_basename, default=None):
		"""
		Get multi options
			option_basename_1=
			option_basename_2=
			...
		"""
		res = list()
		i = 1
		while True:
			cur = self.safe_get(section, '{0}_{1}'.format(option_basename,i), None, allowed=None)
			if not cur:
				break
			res.append(cur)
			i += 1
		return res


	def safe_get_dict(self, section, option, default=None):
		"""
		Get dictionary
		"""
		res = self.safe_get(section, option, default)
		return ast.literal_eval(res) if res else default


	def safe_set(self, section, option, value):
		"""
		Set the given option to the specified value
		Args:
			section (str): Section name
			option (str): Option name
			value (str): Value name
		Returns:
			Bool indicating operation status
		"""
		try:
			configparser.ConfigParser.set(self, section, option, str(value))
			return True
		except:
			#traceback.print_exc()
			return False
