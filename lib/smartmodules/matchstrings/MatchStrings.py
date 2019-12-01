#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from collections import defaultdict

VERSION_REGEXP = '(?P<version>[0-9.]*[0-9])?'

#----------------------------------------------------------------------------------------
# Credentials
#
# Sample:
# creds_match['http'] = {
#     'tool-name': {
#         'found creds: (?P<m1>\S*):(?P<m2>\S*)': {
#             'meth': 'finditer', # optional
#             'user': '$1',
#             'pass': '$2',
#             'type': 'wordpress'
#         },
#         'found user: (?P<m1>\S*)': {
#             'user': '$1'
#         }
#     }
# }
#
# IMPORTANT: A command output might contain several usernames/passwords with the
# same pattern.
# 
# Multiple matching is implemented for each processed regexp.
# 2 Methods of regexp processing are implemented:
# - finditer (default): Use re.finditer(pattern, cmd_output, re.IGNORECASE|re.MULTILINE)
# - search: Use regex.search(pattern, cmd_output, regex.IGNORECASE)
#   This method is particularly useful when we want to match multiple creds, but with 
#   a given prefix located before the list of creds (e.g : CMS Detection:\s*Drupal)
#
# Example method "search":
# >>> m = regex.search('WordPress[\s\S]*?(\[v\] Trying Credentials:\s*(?P<user>\S+)\s*
#                       (?P<password>\S+)\s*\n)+', text)
# >>> m.capturesdict()
# {'user': ['Miniwick', 'Miniwick', 'Miniwick', 'Miniwick', 'Miniwick'], 
# 'password': ['password', 'admin', '123456', 'Password1', 'Miniwick']}
#

creds_match = dict()
from lib.smartmodules.matchstrings.creds.AjpCreds import *
from lib.smartmodules.matchstrings.creds.FtpCreds import *
from lib.smartmodules.matchstrings.creds.HttpCreds import *
from lib.smartmodules.matchstrings.creds.JavaRmiCreds import *
from lib.smartmodules.matchstrings.creds.MssqlCreds import *
from lib.smartmodules.matchstrings.creds.MysqlCreds import *
from lib.smartmodules.matchstrings.creds.OracleCreds import *
from lib.smartmodules.matchstrings.creds.PostgresqlCreds import *
from lib.smartmodules.matchstrings.creds.SmtpCreds import *
from lib.smartmodules.matchstrings.creds.SnmpCreds import *
from lib.smartmodules.matchstrings.creds.SshCreds import *
from lib.smartmodules.matchstrings.creds.TelnetCreds import *
from lib.smartmodules.matchstrings.creds.VncCreds import *


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
# 
# Single matching for each processed regexp.
# Regexp processing using re.search(pattern, cmd_output, re.IGNORECASE|re.MULTILINE)
#

options_match = dict()
from lib.smartmodules.matchstrings.options.FtpOptions import *
from lib.smartmodules.matchstrings.options.HttpOptions import *
from lib.smartmodules.matchstrings.options.JavaRmiOptions import *
from lib.smartmodules.matchstrings.options.OracleOptions import *
from lib.smartmodules.matchstrings.options.SmbOptions import *
from lib.smartmodules.matchstrings.options.SmtpOptions import *
from lib.smartmodules.matchstrings.options.TelnetOptions import *


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
# IMPORTANT: For a given tool, and for a given product, if there are several 
# matchstrings defined, their order is important because it stops after the 
# first match.
#
# Single matching for each processed regexp.
# Regexp processing using re.search(pattern, cmd_output, re.IGNORECASE|re.MULTILINE)
#

products_match = defaultdict(dict)
from lib.smartmodules.matchstrings.products.AjpServerProducts import *
from lib.smartmodules.matchstrings.products.FtpServerProducts import *
from lib.smartmodules.matchstrings.products.HttpWebAppserverProducts import *
from lib.smartmodules.matchstrings.products.HttpWebApplicationFirewallProducts import *
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
# vulns_match['http'] = {
#     'tool-name': {
#         'match string (?P<m1>\S+) lorem ispum': {
#             'name': 'AngularJS Client-Side Template Injection (CSTI)',
#             'location': '$1', # optional
#             'reference': 'CWE-79', # optional
#             'score': '5.3', # must be convertible to float, optional
#             'link': 'https://cwe.mitre.org/data/definitions/79.html', # optional
#             'exploit_available': True/'true'/'1'/1, # optional
#             'exploited': True, # optional
#         },
#     }
# } 
#
# IMPORTANT: A command output might contain several usernames/passwords with the
# same pattern.
#
# Multiple matching is implemented for each processed regexp.
# Regexp processing using re.finditer(pattern, cmd_output, re.IGNORECASE|re.MULTILINE)
#
vulns_match = dict()
from lib.smartmodules.matchstrings.vulns.FtpVulns import *
from lib.smartmodules.matchstrings.vulns.HttpVulns import *
from lib.smartmodules.matchstrings.vulns.JavaRmiVulns import *
from lib.smartmodules.matchstrings.vulns.JdwpVulns import *
from lib.smartmodules.matchstrings.vulns.MssqlVulns import *
from lib.smartmodules.matchstrings.vulns.MysqlVulns import *
from lib.smartmodules.matchstrings.vulns.OracleVulns import *
from lib.smartmodules.matchstrings.vulns.PostgresqlVulns import *
from lib.smartmodules.matchstrings.vulns.RdpVulns import *
from lib.smartmodules.matchstrings.vulns.SmbVulns import *
from lib.smartmodules.matchstrings.vulns.SmtpVulns import *
from lib.smartmodules.matchstrings.vulns.SshVulns import *


#----------------------------------------------------------------------------------------
# OS
#
# Sample:
# os_match = {
#     'Windows': {
#         'banner': [
#              'microsoft',
#              'windows',
#          ],
#          'wappalyzer': [
#              'Windows',
#          ],
#     }
# } 
#
# Single matching for each processed regexp.
# Regexp processing using re.search(pattern, cmd_output, re.IGNORECASE)
#
os_match = dict()
from lib.smartmodules.matchstrings.os.OS import *