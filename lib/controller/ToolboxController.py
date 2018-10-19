# -*- coding: utf-8 -*-
###
### Core > Toolbox Controller
###
from lib.controller.Controller import Controller


class ToolboxController(Controller):

	def run(self):
		service = self.arguments.args.show_toolbox_for_svc or \
				  self.arguments.args.install_for_svc      or \
				  self.arguments.args.update_for_svc       or \
				  self.arguments.args.uninstall_for_svc
		toolname = self.arguments.args.uninstall_tool
		fastmode = self.arguments.args.fast_mode

		if self.arguments.args.show_toolbox_for_svc:
			self.settings.toolbox.show_toolbox(service)
		elif self.arguments.args.show_toolbox_all:
			self.settings.toolbox.show_toolbox()
		elif self.arguments.args.install_for_svc:
			self.settings.toolbox.install_toolbox_service(service, fastmode)
		elif self.arguments.args.install_all:
			self.settings.toolbox.install_toolbox_full(fastmode)
		elif self.arguments.args.update_for_svc:
			self.settings.toolbox.update_toolbox_service(service, fastmode)
		elif self.arguments.args.update_all:
			self.settings.toolbox.update_toolbox_full(fastmode)
		elif self.arguments.args.uninstall_for_svc:
			self.settings.toolbox.remove_toolbox_service(service)
		elif self.arguments.args.uninstall_tool:
			self.settings.toolbox.remove_tool(toolname)
		elif self.arguments.args.uninstall_all:
			self.settings.toolbox.remove_toolbox_full()



