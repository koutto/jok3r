import os
import sys
import traceback
from lib.core import *
from lib.controller import *
from lib.output import *


class Program(object):

	def __init__(self):
		self.script_path = os.path.dirname(os.path.realpath(__file__))
		self.output = CLIOutput(SETTINGS_PRINT_ENABLED)

		# Print banner
		#self.output.printBanner(BANNER)

		try:
			# Read settings from config file
			self.settings = Settings(self.script_path + os.sep + SETTINGS_DIR, self.script_path + os.sep + TOOLBOX_DIR, self.output)

			# Read command-line arguments
			self.arguments = ArgumentsParser(self.settings, self.output)

			# Processing
			self.controller = Controller(self.script_path, self.arguments, self.settings, self.output)

		except KeyboardInterrupt, SystemExit:
			print
			self.output.printError('User aborted')
			sys.exit(0)
		except Exception as e:
			print
			self.output.printError('Unexpected error occured: {0}'.format(str(e)))
			traceback.print_exc()
			sys.exit(0)


if __name__ == '__main__':
    main = Program()