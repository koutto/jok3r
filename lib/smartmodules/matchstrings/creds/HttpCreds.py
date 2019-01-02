#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['http'] = {
    'check-name': {
        'found creds: (?P<m1>\S*):(?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
            'type': 'wordpress'
        },
        'found user: (?P<m1>\S*)': {
            'user': '$1'
        }
    }
}