#!/usr/bin/env python3
# -*- coding: utf-8 -*-

VERSION_REGEXP = '(?P<version>[0-9.]+)?'

#----------------------------------------------------------------------------------------
# Credentials
#
# Sample:
# creds_match['http'] = {
#     'tool-name': {
#         'found creds: (?P<m1>\S*):(?P<m2>\S*)': {
#             'user': '$1',
#             'pass': '$2',
#             'type': 'wordpress'
#         },
#         'found user: (?P<m1>\S*)': {
#             'user': '$1'
#         }
#     }
# }

creds_match = dict()
from lib.smartmodules.matchstrings.creds.HttpCreds import *


#----------------------------------------------------------------------------------------
# Specific Options
#
# Sample:
# options_match['http'] = {
#   'tool-name': {
#       'match string (?P<m1>\S+) lorem ispum': {
#           'name': 'option-name',
#           'value': 'option-value-$1'
#       }
#   }
# }

options_match = dict()


#----------------------------------------------------------------------------------------
# Products
#
# Sample:
# products_match['http']['web-server'] = {
#     'product-name': {
#         'tool-name1': 'lorem ipsum (version: [VERSION])?',
#         'tool-name2': 'lorem ipsum',
#     }
# }

products_match = dict()


#----------------------------------------------------------------------------------------
# Vulnerabilities
#
# Sample:
# vulns_match['http'] = {
#     'tool-name': {
#         'match string (?P<m1>\S+) lorem ispum': 'MS17-010: $1',
#     }
# }

vulns_match = dict()