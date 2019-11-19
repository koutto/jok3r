#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

CMSEEK_REGEXP = '"cms_name":\s*"{}"(,[\s\S]*"cms_version":\s*"[VERSION]")?'
WIG_REGEXP = '{}\s*[VERSION]\s*Platform' 
WIG_REGEXP2 = '- Found platform {}(\s*[VERSION])?'


products_match['http']['web-language'] = {
    'AsciiDoc': {
        'wappalyzer': 'AsciiDoc',
        'cmseek': CMSEEK_REGEXP.format('AsciiDoc'),
    },
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
    'Dart': {
        'wappalyzer': 'Dart',
    },
    'Erlang': {
        'wappalyzer': 'Erlang',
    },
    'Haskell': {
        'wappalyzer': 'Haskell',
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
    'Rdf': {
        'wappalyzer': 'Rdf',
    },
    'Ruby': {
        'wappalyzer': 'Ruby',
    },
    'Scala': {
        'wappalyzer': 'Scala',
    },
}
