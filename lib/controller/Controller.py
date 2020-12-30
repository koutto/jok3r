#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Controller (interface)
###

class Controller:

    def __init__(self, arguments, settings, sqlsession):
        """
        Controller interface.

        :param ArgumentsParser arguments: Arguments from command-line
        :param Settings settings: Settings from config files
        :param Session sqlsession: SQLAlchemy session
        """
        self.arguments = arguments
        self.settings  = settings
        self.sqlsess   = sqlsession



