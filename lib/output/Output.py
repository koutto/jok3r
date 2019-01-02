#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Output > Command-Line Output
###
import os
import sys
import colored
import prettytable
import humanfriendly.prompts
#import humanfriendly.tables

from lib.output.Logger import logger


class Output(object):

    @staticmethod
    def print(string, color=None, highlight=None, attrs=None):
        """Print string with styles"""
        print(Output.colored(string, color, highlight, attrs))


    @staticmethod
    def colored(string, color=None, highlight=None, attrs=None):
        """Apply styles to a given string"""
        # Colors list: https://pypi.org/project/colored/
        return colored.stylize(string, (colored.fg(color) if color else '') + \
                                       (colored.bg(highlight) if highlight else '') + \
                                       (colored.attr(attrs) if attrs else ''))

    @staticmethod
    def bold(string):
        """Print string in bold"""
        return colored.stylize(string, colored.attr('bold'))


    @staticmethod
    def print_with_tabs(string, color=None, highlight=None, attrs=None):
        """Print string prefixed by a tabulation"""
        Output.print('         '+string, color, highlight, attrs)


    @staticmethod
    def print_inline(string):
        """Print at the same location (erase and print)"""
        sys.stdout.write('\033[1K')
        sys.stdout.write('\033[0G')
        sys.stdout.write(string)
        sys.stdout.flush()


    @staticmethod
    def banner(banner):
        """Print banner"""
        Output.print(banner, color='light_green', attrs='bold')


    @staticmethod
    def title1(title):
        """Print title level 1"""
        msg  = '\n'
        msg += '-'*80 + '\n'
        msg += ' {title}\n'.format(title=title)
        msg += '-'*80 + '\n'
        Output.print(msg, color='light_green', attrs='bold')


    @staticmethod
    def title2(title):
        """Print title level 2"""
        Output.print('[>] ' + title, color='light_yellow', attrs='bold')


    @staticmethod
    def title3(title):
        """Print title level 3"""
        Output.print('[>] ' + title, attrs='bold')


    @staticmethod
    def begin_cmd(cmd):
        """Print command-line and beginning delimiter for output"""
        # If command-line starts with "cd" command, remove it for better readability
        if cmd.startswith('cd'):
            cmd = cmd[cmd.index(';')+1:].strip()
        _, col = (lambda x: (int(x[0]), int(x[1])))(os.popen('stty size', 'r')\
                                                      .read().split())
        msg  = '\n'
        msg += ' ' * col + '\n'
        msg += 'cmd> {cmd}'.format(cmd=cmd) + ' ' * (col - (len(cmd)+5) % col) + '\n'
        #msg += ' ' * col + '\n'
        Output.print(msg, color='white', highlight='grey_19', attrs='bold')


    @staticmethod
    def delimiter():
        """Print ending delimiter for command output"""
        _, col = (lambda x: (int(x[0]), int(x[1])))(os.popen('stty size', 'r')\
                                                      .read().split())
        msg  = '\n'
        msg += ' ' * col + '\n'
        #msg += ' ' * col + '\n'     
        Output.print(msg, color='white', highlight='grey_19', attrs='bold')


    @staticmethod
    def prompt_confirm(question, default=None):
        """
        Prompt for confirmation.
        :param str question: Question to print
        :param str default: Default answer
        """
        return humanfriendly.prompts.prompt_for_confirmation(
            colored.stylize('[?] ', colored.fg('cyan')+colored.attr('bold'))+question,
            default=default, padding=False)


    @staticmethod
    def prompt_choice(question, choices, default=None):
        """
        Prompt choice.
        :param str question: Question to print
        :param dict choices: Possible choices
            Example: {'y': 'Yes', 'n': 'No', 'q': 'Quit'}
        :param str default: Default answer
        """
        while True:
            ret = humanfriendly.prompts.prompt_for_input(
                colored.stylize('\b[?] ', colored.fg('cyan')+colored.attr('bold')) \
                    + question, default=default)

            if ret.lower() in choices: return ret.lower()
            else:
                valid = ' / '.join('{} = {}'.format(key,val) \
                    for key,val in choices.items())
                logger.warning('Invalid value. Valid values are: ' + valid)
        return default


    @staticmethod
    def prompt_choice_range(question, mini, maxi, default):
        """
        Prompt choice in a range [mini-maxi].
        :param str question: Question to print
        :param int mini: Minimum number in range
        :param int maxi: Maximum number in range
        :param int default: Default answer
        """
        while True:
            try:
                ret = int(humanfriendly.prompts.prompt_for_input(
                    colored.stylize('\b[?] ', colored.fg('cyan')+colored.attr('bold'))+ \
                    question, default=default))
            except ValueError:
                continue
            if mini <= ret <= maxi: 
                return ret
            else:
                logger.warning('Invalid value. Valid values are in range ' \
                    '[{mini}-{maxi}]'.format(mini=mini, maxi=maxi))
        return default


    @staticmethod
    def prompt_choice_verbose(choices, default=None):
        """Prompt choice in verbose mode"""
        return humanfriendly.prompts.prompt_for_choice(choices, 
            default=default, padding=False)


    @staticmethod
    def table(columns, data, hrules=True):
        """
        Print a table. Supports multi-row cells.
        :param columns: An iterable of column names (strings)
        :param data: An iterable containing the data of the table
        :param hrules: Boolean for horizontal rules
        """
        columns = map(lambda x:Output.colored(x, attrs='bold'), columns)
        table = prettytable.PrettyTable(
            hrules=prettytable.ALL if hrules else prettytable.FRAME, 
            field_names=columns)
        for row in data:
            table.add_row(row)
        table.align = 'l'
        print(table)
            

    # @staticmethod
    # def table(columns, data, mode_row=True):
    #     if not mode_row:
    #         nbcols = len(cols)
    #         maxcollen = len(max(d, key=len))
    #         newdata = list([] for x in range(maxcollen))
    #         for i in range(maxcollen):
    #             newdata[i] = list('' for x in range(nbcols))
    #             for j in range(nbcols):
    #                 if i<len(data[j]):
    #                     newdata[i][j] = data[j][i]
    #         data = newdata         
    #     print humanfriendly.tables.format_pretty_table(data, columns)

