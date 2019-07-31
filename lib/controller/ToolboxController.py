#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Toolbox Controller
###
from lib.controller.Controller import Controller


class ToolboxController(Controller):

    def run(self):

        service = self.arguments.args.show_toolbox_for_svc \
            or self.arguments.args.install_for_svc \
            or self.arguments.args.update_for_svc \
            or self.arguments.args.uninstall_for_svc

        toolname = self.arguments.args.install_tool \
            or self.arguments.args.update_tool \
            or self.arguments.args.uninstall_tool

        # --fast
        fastmode = self.arguments.args.fast_mode

        # --show <service>
        if self.arguments.args.show_toolbox_for_svc:
            self.settings.toolbox.show_toolbox(service)

        # --show-all
        elif self.arguments.args.show_toolbox_all:
            self.settings.toolbox.show_toolbox()

        # --install <service>
        elif self.arguments.args.install_for_svc:
            self.settings.toolbox.install_for_service(service, fastmode)

        # --install-tool <tool-name>
        elif self.arguments.args.install_tool:
            self.settings.toolbox.install_tool(toolname, fastmode)

        # --install-all
        elif self.arguments.args.install_all:
            self.settings.toolbox.install_all(fastmode)

        # --update <service>
        elif self.arguments.args.update_for_svc:
            self.settings.toolbox.update_for_service(service, fastmode)

        # --update-tool <tool-name>
        elif self.arguments.args.update_tool:
            self.settings.toolbox.update_tool(toolname, fastmode)

        # --update-all
        elif self.arguments.args.update_all:
            self.settings.toolbox.update_all(fastmode)

        # --uninstall <service>
        elif self.arguments.args.uninstall_for_svc:
            self.settings.toolbox.remove_toolbox_service(service)

        # --uninstall-tool <tool-name>
        elif self.arguments.args.uninstall_tool:
            self.settings.toolbox.remove_tool(toolname)

        # --uninstall-all
        elif self.arguments.args.uninstall_all:
            self.settings.toolbox.remove_all()

        # --check
        elif self.arguments.args.check_toolbox:
            self.settings.toolbox.check()




