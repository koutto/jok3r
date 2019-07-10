#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > ArgParseUtils
###
import argparse
import textwrap

from lib.core.Config import *


class LineWrapRawTextHelpFormatter(argparse.RawDescriptionHelpFormatter):

    def _split_lines(self, text, width):
        """
        For custom max width
        """
        #text = self._whitespace_matcher.sub(' ', text).strip()
        #return textwrap.wrap(text, ARGPARSE_MAX_WIDTH)
        return text.splitlines()


    def _format_args(self, action, default_metavar):
        """
        For multi args (nargs >= 2), do not use default syntax (ARG [ARG ...])
        """
        get_metavar = self._metavar_formatter(action, default_metavar)
        if action.nargs == argparse.ONE_OR_MORE:
            return get_metavar(1)[0]
        else:
            return super()._format_args(action, default_metavar)


    def _format_action_invocation(self, action):
        """
        Custom for concatenation short and long option with only one occurrence of metavar
        """
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            metavar, = self._metavar_formatter(action, default)(1)
            return metavar
        else:
            parts = []

            # If the Optional doesn't take a value, format is: -s, --long
            if action.nargs == 0:
                parts.extend(action.option_strings)

            # If the Optional takes a value, format is: -s ARGS, --long ARGS
            else:
                default = self._get_default_metavar_for_optional(action)
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append(option_string)

                return '%s %s' % (', '.join(parts), args_string)

            return ', '.join(parts)


    def _get_default_metavar_for_optional(self, action):
        return action.dest.upper()


    def _get_default_metavar_for_positional(self, action):
        return action.dest.upper()


#----------------------------------------------------------------------------------------

class Store1or2Append(argparse._AppendAction):
    """
    Dirty hack !
    Custom action for 1-2 length for argparse option in append mode
    """
    def __call__(self, parser, namespace, values, option_string=None):
        if not (1 <= len(values) <= 2):
            raise argparse.ArgumentError(self, "%s takes 1 or 2 values, %d given" % \
                (option_string, len(values)))
        super(Store1or2Append, self).__call__(parser, namespace, values, option_string)


class Store2or3Append(argparse._AppendAction):
    """
    Dirty hack !
    Custom action for 2-3 length for argparse option in append mode
    """
    def __call__(self, parser, namespace, values, option_string=None):
        if not (2 <= len(values) <= 3):
            raise argparse.ArgumentError(self, "%s takes 2 or 3 values, %d given" % \
                (option_string, len(values)))
        super(Store2or3Append, self).__call__(parser, namespace, values, option_string)


#----------------------------------------------------------------------------------------

def nargs_req_length(nmin, nmax):
    """
    Custom action for required length for argparse option
    https://stackoverflow.com/questions/4194948/python-argparse-is-there-a-way-to-specify-a-range-in-nargs

    parser=argparse.ArgumentParser(prog='PROG')
    parser.add_argument('-f', nargs='+', action=required_length(2,3))

    >>> args=parser.parse_args('-f 1 2 3'.split())
    >>> print args
    Namespace(f=['1', '2', '3'])
    >>> args=parser.parse_args('-f 1 '.split())
    Traceback (most recent call last):
    argparse.ArgumentTypeError: argument "f" requires between 2 and 3 arguments
    """
    class RequiredLength(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            if not nmin<=len(values)<=nmax:
                msg='argument "{f}" requires between {nmin} and {nmax} arguments'.format(
                    f=self.dest, nmin=nmin, nmax=nmax)
                raise argparse.ArgumentTypeError(msg)
            setattr(args, self.dest, values)
    return RequiredLength




