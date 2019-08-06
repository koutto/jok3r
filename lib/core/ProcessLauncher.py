#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Process Launcher
###
import subprocess
import sys

from lib.output.Logger import logger

class ProcessLauncher:

    def __init__(self, command):
        """
        :param str command: Command line
        """
        self.command = command.strip()


    #------------------------------------------------------------------------------------

    def start(self):
        """
        Start process in current terminal

        :return: Command output
        :rtype: str
        """
        return self.__create_subprocess(self.command)


    def start_in_new_window(self, title=None):
        """
        Start process in new terminal.
        gnome-terminal is used. 
        TODO: Might be adapted for other platforms (xterm...)

        :param title: Title for the new window
        :return: Command output
        :rtype: str
        """
        cmd =  'gnome-terminal '
        if title is not None:
            cmd += '--title="{0}" '.format(title.replace('"', '\\"'))
        cmd += '--geometry=140x80 '
        cmd += '--command="bash -c \'{0}; exec bash\'"'.format(self.command)
        return self.__create_subprocess(cmd)


    def start_in_new_tab(self):
        """
        Start process in new tab in current terminal session.
        Use a dirty hack to open tab (https://gist.github.com/Raboo/5361942).

        :return: Command output
        :rtype: str
        """
        cmd  = 'WID=$(xprop -root | grep "_NET_ACTIVE_WINDOW(WINDOW)"| '
        cmd += 'awk \'{print $5}\');'
        cmd += 'xdotool windowfocus $WID;'
        cmd += 'xdotool key ctrl+shift+t;'
        cmd += 'xdotool type "{0}";'.format(self.command)
        cmd += 'xdotool key Return'
        return self.__create_subprocess(cmd)
        # TOTEST: Stdout ?


    #------------------------------------------------------------------------------------

    def __create_subprocess(self, cmd):
        """
        Run a command. Display output (stdout+stderr) in live and also store it into
        a variable which is returned by the function.
        Commands are run using Bash shell (required to be able to run built-in 
        commands such as "source" in some cases such as virtualenv activation)

        :param str cmd: Command to execute
        :return: Command output (stdout+stderr)
        :rtype: str
        """
        returncode = None
        output = ''
        
        try:
            proc = subprocess.Popen(cmd, 
                                    shell=True, 
                                    executable='/bin/bash',
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.STDOUT)

            # for line in iter(proc.stdout.readline, b''):
            #     out = line.decode(sys.stdout.encoding)
            #     sys.stdout.write(out)
            #     output += out

            #output = proc.stdout.read()
            #print(output)


            # Agressivelly get the output
            while True:
                out = proc.stdout.read(1)
                # We put that inside try block to avoid utf8 decoding error
                try:
                    out = out.decode(sys.stdout.encoding)
                    sys.stdout.write(out)
                    output += out
                except:
                    pass

                # Break if process has finished
                if out == ''  and proc.poll() != None:
                    returncode = proc.returncode
                    break

        except Exception as e:
            logger.error('Error when trying to run command: {exception}'.format(
                exception=e))

        return (returncode, output)