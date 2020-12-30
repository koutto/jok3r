#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# We consider as version only the year, e.g. 2012, 2014...
# The exact version number (e.g. 12.00.2000) is not taken into account
# in smartmodules.
# This choice is motivated by the fact that Vulners.com API and 
# Cvedetails.com does not fully take into account those exact version
# numbers.
#
# Examples:
# product: Microsoft SQL Server 2014 version: 12.00.2000
# product: Microsoft SQL Server 2012 version: 11.00.7001
# product: Microsoft SQL Server 2012 version: 11.00.6020; SP3 

products_match['mssql']['mssql-server'] = {
    'Microsoft/SQL Server': {
        'banner': 'Microsoft SQL Server(\s+[VERSION])?',

        # Msdat mssqlinfo output example:
        # [+] SQL Server Browser is enabled on the server x.x.x.x:1434:
        # -> ServerName: HOST
        # -> tcp: 1433
        # -> ProductName: SQL Server 2008 R2 (no SP)
        # -> IsClustered: No
        # -> Version: 10.50.1600.1
        # -> InstanceName: MSSQLSERVER
        
        #'msdat': 'Version:\s*[VERSION]',
        'msdat': 'ProductName: SQL Server [VERSION]'
    },
}