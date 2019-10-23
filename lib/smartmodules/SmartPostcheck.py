#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### SmartModules > Smart Postcheck
###
import re

from lib.output.Logger import logger
from lib.smartmodules.ContextUpdater import ContextUpdater
from lib.smartmodules.MatchstringsProcessor import MatchstringsProcessor


class SmartPostcheck:

    def __init__(self, 
                 service, 
                 tool_name, 
                 cmd_output):
        """
        SmartPostcheck class allows to run code after a check during an attack 
        against one service. It is useful to analyze/process command outputs
        and to update context accordingly.

        :param Service service: Target service db model
        :param str tool_name: Name of the check that has been run before
        :param str cmd_output: Command output (sanitized / special chars removed)
            Important: output is prepended by command line
        """
        self.service = service
        self.tool_name = tool_name
        self.cmd_output = cmd_output
        self.cu = ContextUpdater(self.service)
        self.processor = MatchstringsProcessor(self.service, 
                                               self.tool_name,
                                               self.cmd_output,
                                               self.cu)


    def run(self):
        """Run postcheck processing"""

        logger.smartinfo('SmartPostcheck processing to update context...')
        self.processor.detect_credentials()
        self.processor.detect_specific_options()
        self.processor.detect_products()
        self.processor.detect_vulns()
        self.cu.update()

        if self.tool_name == 'nmap':
            self.__check_banner_nmap()


    def __check_banner_nmap(self):
        """
        Additional method run when the tool is Nmap.
        Product detection is performed using regexp "banner" if available
        on the line from output that corresponds to the banner, e.g. :

        PORT   STATE SERVICE REASON  VERSION
        21/tcp open  ftp     syn-ack ProFTPD 1.2.10
        """
        m = re.search('^[0-9]+/tcp\s+open\s+\S+\s+\S+\s+?(?P<banner>.*?)$', self.cmd_output, re.MULTILINE)
        if m:
            if m.group('banner'):
                self.processor = MatchstringsProcessor(self.service, 
                                                       'banner',
                                                       m.group('banner'),
                                                       self.cu)
                self.processor.detect_products()
                self.cu.update()

