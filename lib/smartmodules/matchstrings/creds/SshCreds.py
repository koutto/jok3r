#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['ssh'] = {

    'hydra': {
        '\[ssh\] host: \S+\s+login:\s+(?P<m1>\S+)\s+password: (?P<m2>\S*)': {
            'user': '$1',
            'pass': '$2',
        },
    },
    'osueta': {
        '\[\+\] User: (?P<m1>\S+) exists': {
            'user': '$1',
        },
    },
    'ssh-user-enum-cve2018-15473': {
        '\[\+\] (?P<m1>\S+) found!': {
            'user': '$1',
        },
    },
}