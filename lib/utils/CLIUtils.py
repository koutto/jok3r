###
### utils > CLIUtils
###

import time
import sys
import tty
import termios

class CLIUtils(object):

	@staticmethod
	def readInput(default=None):
	    """
	    Reads input from terminal
	    @Args 	default (str): Default value to return if no input is given
	    """
	    retval = None
	    sys.stdout.write('> ')
	    sys.stdout.flush()
	    try:
	    	retval = raw_input() or default
	    except Exception as e:
	    	time.sleep(0.05)

	    return retval

	@staticmethod
	def getch():
		"""
		Implementation of getchar(), used for "Press any key" UI behaviour
		"""
		fd = sys.stdin.fileno()
		old_settings = termios.tcgetattr(fd)
		try:
		    tty.setraw(fd)
		    ch = sys.stdin.read(1)
		finally:
		    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
		return ch

	@staticmethod
	def promptYesNo(output, default='Y'):
		"""
		Basic Yes/No prompt 
		@Args	default (char): default value - 'Y' for yes, 'N' for no
				output: instance of CLIOutput
		@Return boolean
		"""
		while True:
			inp = CLIUtils.readInput(default)
			if inp.lower() == 'y':
				retval = True
				break
			if inp.lower() == 'n':
				retval = False
				break
			else:
				output.printWarning('Invalid value. Y=Yes / N=No')
		return retval

	@staticmethod
	def promptRunMode(output, default='Y'):
		"""
		"""
		while True:
			inp = CLIUtils.readInput(default)
			if inp.lower() == 'y':
				retval = 'Yes'
				break
			elif inp.lower() == 'n':
				retval = 'No'
				break
			elif inp.lower() == 't':
				retval = 'Tab'
				break
			elif inp.lower() == 'w':
				retval = 'Window'
				break
			elif inp.lower() == 'q':
				retval = 'Quit'
				break
			else:
				output.printWarning('Invalid value. Valid values are: Y=Yes / N=No / T=Start in tab / W=Start in new window / Q=quit')
		return retval