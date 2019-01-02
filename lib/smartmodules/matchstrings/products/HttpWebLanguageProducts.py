#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match


products_match['http']['web-language'] = {
    'product-name': {
        'check-name1': 'lorem ipsum (version: [VERSION])?',
        'check-name2': 'lorem ipsum',
    }
}
