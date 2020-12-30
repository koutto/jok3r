#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import options_match


options_match['smtp'] = {
    
    'service-name-original': {
        'smtps': {
            'name': 'smtps',
            'value': 'true',
        },
    },
    'banner': {
        'smtps(\s|\.)': {
            'name': 'smtps',
            'value': 'true',
        },
    },

}