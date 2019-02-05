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
# 
# For a given product-name, and a given tool-name, it is also possible to specify
# several matchstrings using list as follows:
#     'Apache/Tomcat' : {
#         'clusterd': [
#             'Matched [0-9]+ fingerprints for service tomcat',
#             'Tomcat (Manager|Admin)? \(version [VERSION]',
#          ],
#      }

products_match = dict()
from lib.smartmodules.matchstrings.products.AjpServerProducts import *
from lib.smartmodules.matchstrings.products.FtpServerProducts import *
from lib.smartmodules.matchstrings.products.HttpWebCmsProducts import *
from lib.smartmodules.matchstrings.products.HttpWebFrameworkProducts import *
from lib.smartmodules.matchstrings.products.HttpWebJslibProducts import *
from lib.smartmodules.matchstrings.products.HttpWebLanguageProducts import *
from lib.smartmodules.matchstrings.products.HttpWebServerProducts import *
from lib.smartmodules.matchstrings.products.JavaRmiServerProducts import *
from lib.smartmodules.matchstrings.products.MssqlServerProducts import *
from lib.smartmodules.matchstrings.products.MysqlServerProducts import *
from lib.smartmodules.matchstrings.products.OracleServerProducts import *
from lib.smartmodules.matchstrings.products.PostgresqlServerProducts import *
from lib.smartmodules.matchstrings.products.SmtpServerProducts import *
from lib.smartmodules.matchstrings.products.SshServerProducts import *





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