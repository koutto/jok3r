#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > CLIUtils
###
import sys
import tty
import termios
import readline

class CLIUtils:

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
    def edit_string_inline(default):
        """
        TODO
        """
        readline.set_startup_hook(lambda: readline.insert_text(default))
        res = raw_input('Edit > ')
        #print res

