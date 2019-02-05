#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['snmp'] = {

    'metasploit': {
        'Login Successful: (?P<m1>\S+)': {
            'user': '$1',
        },
    },

}