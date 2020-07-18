#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['java-rmi'] = {

    'jmxbf': {
        'We got a valid connection for: (?P<m1>\S*):(?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
        },
    },

}