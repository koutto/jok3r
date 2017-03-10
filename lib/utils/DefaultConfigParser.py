###
### ConfigParser subclass used for safe configuration file parsing 
###

import ConfigParser
import traceback

class DefaultConfigParser(ConfigParser.ConfigParser):

	def __init__(self):
		ConfigParser.ConfigParser.__init__(self, allow_no_value=True)


	def safeGet(self, section, option, default, allowed=None):
		"""
		Get a string with exception handling
		"""
		try:
			result = ConfigParser.ConfigParser.get(self, section, option)
			if allowed is not None:
				return result if result in allowed else default
			else:
				return result
		except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
			return default


	def safeGetFloat(self, section, option, default, allowed=None):
		"""
		Get a float with exception handling
		"""
		try:
			result = ConfigParser.ConfigParser.getfloat(self, section, option)
			if allowed is not None:
				return result if result in allowed else default
			else:
				return result
		except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
			return default


	def safeGetBoolean(self, section, option, default):
		"""
		Get a boolean with exception handling
		"""
		try:
			result = ConfigParser.ConfigParser.getboolean(self, section, option)
			return result if isinstance(result, bool) else default
		except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
			return default


	def safeGetInt(self, section, option, default, allowed=None):
		"""
		Get an integer with exception handling
		"""
		try:
			result = ConfigParser.ConfigParser.getint(self, section, option)
			if allowed is not None:
				return result if result in allowed else default
			else:
				return result
		except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
			return default


	def safeGetList(self, section, option, sep=',', default=None):
		"""
		Get a list with exception handling
		"""
		try:
			result_str = self.safeGet(section, option, None, None)
			if result_str is not None:
				return [ e.strip() for e in result_str.split(sep) ]
			else:
				return default
		except:
			return default

	def safeSet(self, section, option, value):
		"""
		Set the given option to the specified value
		Args:
			section (str): Section name
			option (str): Option name
			value (str): Value name
		Returns:
			Bool indicating operation status
		"""
		ConfigParser.ConfigParser.set(self, section, option, str(value))
		return True
		try:
			ConfigParser.ConfigParser.set(self, section, option, value)
			return True
		except:
			traceback.print_exc()
			return False
