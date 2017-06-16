###
### utils > CmdUtils
###


class CmdUtils(object):

	@staticmethod
	def removeArgsFromCmd(cmd):
		"""
		Remove arguments from a command line
		Example:
			- input:  sudo python toolname.py -a 'abc' -b 'def' -c
			- output: sudo python toolname.py

		@Args 	cmd: 	Command line
		"""

		cmdsplit = cmd.strip().split(' ')
		newcmd = ''

		if cmdsplit[0].lower() == 'sudo' and len(cmdsplit) > 1:
			newcmd = 'sudo '
			cmdsplit = cmdsplit[1:]

		newcmd += cmdsplit[0]
		if cmdsplit[0].lower() in ('python', 'python3', 'perl', 'ruby') and len(cmdsplit) > 1:
			if cmdsplit[1] != '-m':
				newcmd += ' ' + cmdsplit[1]
			elif len(cmdsplit) > 2:
				newcmd += ' -m ' + cmdsplit[2]

		elif cmdsplit[0].lower() == 'java' and len(cmdsplit) > 1:
			if cmdsplit[1] != '-jar':
				newcmd += ' ' + cmdsplit[1]
			elif len(cmdsplit) > 2:
				newcmd += ' -jar ' + cmdsplit[2]

		return newcmd
