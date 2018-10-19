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
        print(Output.colored(string, color, highlight, attrs))


    @staticmethod
    def colored(string, color=None, highlight=None, attrs=None):
        # Colors list: https://pypi.org/project/colored/
        return colored.stylize(string, (colored.fg(color) if color else '') + \
                                       (colored.bg(highlight) if highlight else '') + \
                                       (colored.attr(attrs) if attrs else ''))

    @staticmethod
    def bold(string):
        return colored.stylize(string, colored.attr('bold'))


    @staticmethod
    def print_with_tabs(string, color=None, highlight=None, attrs=None):
        Output.print('         '+string, color, highlight, attrs)


    @staticmethod
    def print_inline(string):
        sys.stdout.write('\033[1K')
        sys.stdout.write('\033[0G')
        sys.stdout.write(string)
        sys.stdout.flush()


    @staticmethod
    def banner(banner):
        Output.print(banner, color='light_green', attrs='bold')


    @staticmethod
    def title1(title):
        msg  = '\n'
        msg += '------------------------------------------------------------------------------\n'
        msg += ' {title}\n'.format(title=title)
        msg += '------------------------------------------------------------------------------\n'
        Output.print(msg, color='light_green', attrs='bold')


    @staticmethod
    def title2(title):
        Output.print('[>] ' + title, color='light_yellow', attrs='bold')


    @staticmethod
    def title3(title):
        Output.print('[>] ' + title, attrs='bold')


    @staticmethod
    def begin_cmd(cmd):
        # If command-line starts with "cd" command, remove it for better readability
        if cmd.startswith('cd'):
            cmd = cmd[cmd.index(';')+1:].strip()
        _, col = (lambda x: (int(x[0]), int(x[1])))(os.popen('stty size', 'r').read().split())
        msg  = '\n'
        msg += ' ' * col + '\n'
        msg += 'cmd> {cmd}'.format(cmd=cmd) + ' ' * (col - (len(cmd)+5) % col) + '\n'
        #msg += ' ' * col + '\n'
        Output.print(msg, color='white', highlight='grey_19', attrs='bold')


    @staticmethod
    def delimiter():
        _, col = (lambda x: (int(x[0]), int(x[1])))(os.popen('stty size', 'r').read().split())
        msg  = '\n'
        msg += ' ' * col + '\n'
        #msg += ' ' * col + '\n'     
        Output.print(msg, color='white', highlight='grey_19', attrs='bold')


    @staticmethod
    def prompt_confirm(question, default=None):
        return humanfriendly.prompts.prompt_for_confirmation(colored.stylize(
            '[?] ', colored.fg('cyan') + colored.attr('bold'))+question, default=default, padding=False)


    @staticmethod
    def prompt_choice(question, choices, default=None):
        """
        :param choices: Dict. example: {'y': 'Yes', 'n': 'No', 'q': 'Quit'}
        """
        while True:
            ret = humanfriendly.prompts.prompt_for_input(colored.stylize(
                '\b[?] ', colored.fg('cyan') + colored.attr('bold'))+question, default=default)
            if ret.lower() in choices: return ret.lower()
            else:
                valid = ' / '.join('{} = {}'.format(key,val) for key,val in choices.items())
                logger.warning('Invalid value. Valid values are: ' + valid)
        return default


    @staticmethod
    def prompt_choice_range(question, mini, maxi, default):
        while True:
            try:
                ret = int(humanfriendly.prompts.prompt_for_input(colored.stylize(
                    '\b[?] ', colored.fg('cyan') + colored.attr('bold'))+question, default=default))
            except ValueError:
                continue
            if mini <= ret <= maxi: 
                return ret
            else:
                logger.warning('Invalid value. Valid values are in range [{mini}-{maxi}]'.format(
                    mini=mini, maxi=maxi))
        return default


    @staticmethod
    def prompt_choice_verbose(choices, default=None):
        return humanfriendly.prompts.prompt_for_choice(choices, default=default, padding=False)


    @staticmethod
    def table(columns, data, hrules=True):
        """
        Print a table. Supports multi-row cells.
        :param columns: An iterable of column names (strings)
        :param data: An iterable containing the data of the table
        :param hrules: Boolean for horizontal rules
        """
        columns = map(lambda x:Output.colored(x, attrs='bold'), columns)
        table = prettytable.PrettyTable(hrules=prettytable.ALL if hrules else prettytable.FRAME, field_names=columns)
        for row in data:
            table.add_row(row)
        table.align = 'l'
        print(table)
            

    # @staticmethod
    # def table(columns, data, mode_row=True):
    #     """
    #     :param columns: An iterable of column names (strings)
    #     :param data: An iterable containing the data of the table
    #     :param mode_row: If True (default), data must contain an iterable of the rows of the table
    #                       (where each row is an iterable containing the columns). If False, data must
    #                       contain an iterable of the columns of the table (inverse).
    #     """
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

