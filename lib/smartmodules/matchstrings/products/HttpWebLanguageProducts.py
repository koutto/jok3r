#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

WIG_REGEXP = '- Found platform {}(\s*[VERSION])?'
WIG_REGEXP2 = '{}\s*[VERSION]\s*Platform' 

products_match['http']['web-language'] = {
    'Microsoft/ASP.NET': {
        'wappalyzer': 'Microsoft ASP.NET',
        'wig': [
            WIG_REGEXP.format('ASP\.NET'),
            WIG_REGEXP2.format('ASP\.NET'),
        ],
    },
    'CFML': {
        'wappalyzer': 'CFML',
    },
    'Go': {
        'wappalyzer': 'Go',
    },
    'Java': {
        'wappalyzer': 'Java',
    },
    'Lua': {
        'wappalyzer': 'Lua',
    },
    'Node.js': {
        'wappalyzer': 'Node.js',
    },
    'Perl': {
        'wappalyzer': 'Perl',
    },
    'PHP': {
        'wappalyzer': 'PHP',
        'wig': [
            WIG_REGEXP.format('PHP'),
            WIG_REGEXP2.format('PHP'),
        ],
    },
    'Python': {
        'wappalyzer': 'Python',
    },
    'Ruby': {
        'wappalyzer': 'Ruby',
    },
}
