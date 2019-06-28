#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import options_match


options_match['oracle'] = {
    
    'odat': {
        'ALIAS=(LISTENER_)?(?P<m1>[a-zA-Z0-9]+)\)': {
            'name': 'sid',
            'value': '$1',
        },
    },

}