#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Main Controller
###
from lib.core.Constants import *
from lib.controller.Controller import Controller
from lib.controller.ToolboxController import ToolboxController
from lib.controller.InfoController import InfoController
from lib.controller.DbController import DbController
from lib.controller.AttackController import AttackController


class MainController(Controller):

    def run(self):
        """Run the adapted controller"""
        {
            Mode.TOOLBOX : ToolboxController,
            Mode.INFO    : InfoController,
            Mode.DB      : DbController,
            Mode.ATTACK  : AttackController,
        }.get(self.arguments.mode)(self.arguments, self.settings, self.sqlsess).run()


