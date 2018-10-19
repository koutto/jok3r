# -*- coding: utf-8 -*-
###
### Core > Controller (interface)
###

class Controller:

    def __init__(self, arguments, settings, sqlsession):
        self.arguments = arguments
        self.settings  = settings
        self.sqlsess   = sqlsession



