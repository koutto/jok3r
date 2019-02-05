#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# TODO: Handle exact version number in addition to the date
#
# Examples:
# product: Microsoft SQL Server 2014 version: 12.00.2000
# product: Microsoft SQL Server 2012 version: 11.00.7001
# product: Microsoft SQL Server 2012 version: 11.00.6020; SP3 

products_match['mssql']['mssql-server'] = {
    'Microsoft/SQL Server': {
        'nmap': 'Microsoft SQL Server(\s+[VERSION])?',
    },
}