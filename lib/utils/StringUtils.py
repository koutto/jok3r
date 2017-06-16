

class StringUtils(object):

	@staticmethod
	def cleanSpecialChars(string):
		"""
		Only keep alphanum chars and -, _, <space>
		"""
		return "".join(c for c in string if c.isalnum() or c in ('_','-','.',' '))