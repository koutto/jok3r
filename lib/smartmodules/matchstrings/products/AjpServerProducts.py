#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

products_match['ajp']['ajp-server'] = {
    'Apache/Jserv': {
        'nmap-banner': 'Apache Jserv(\s+[VERSION])?',
    },
    'Apache/Tomcat': {
        'ajpy': 'Apache Tomcat/[VERSION]',
    }
}