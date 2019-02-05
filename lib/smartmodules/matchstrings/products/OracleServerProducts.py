#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# Examples: 
# product: Oracle TNS listener version: 12.1.0.2.0 

products_match['oracle']['oracle-server'] = {
    'Oracle/Database Server': {
        'nmap': 'Oracle (Database|TNS Listener)(\s+[VERSION])?',
    },
}