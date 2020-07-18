#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match


products_match['postgresql']['postgresql-server'] = {
    'Postgresql': {
        'banner': 'PostgreSQL (DB)?(\s*[VERSION])?',
    },
}