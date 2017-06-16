###
### Controller
###

import sys
import time
from lib.output import *
from lib.controller.ToolboxManager import ToolboxManager
from lib.controller.ToolsRunner import ToolsRunner


class Controller(object):

    def __init__(self, arguments, settings, output):
        self.settings     = settings
        self.arguments    = arguments
        self.output       = output


    def run(self):

        # Toolbox management
        toolbox_manager = ToolboxManager(self.arguments, self.settings, self.output)
        toolbox_manager.run()

        # Tools running
        begin = time.time()
        tools_runner = ToolsRunner(self.arguments, self.settings, self.output)
        tools_runner.run()
        print
        self.output.printInfo('Processing terminated - time spent: {0} seconds'.format(int(time.time()-begin)))
