#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['ssh'] = {

    'osueta': {
        '\[\+\] User: (?P<m1>\S+) exists': {
            'user': '$1',
        },
    },

}