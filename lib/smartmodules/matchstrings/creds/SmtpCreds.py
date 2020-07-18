#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import creds_match


creds_match['smtp'] = {

    'smtp-user-enum': {
        ': (?P<m1>\S+) exists': {
            'user': '$1',
        },
    },

}