#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match


WIG_REGEXP = '{}\s*[VERSION]\s*CMS' 
WIG_REGEXP2 = '- Found CMS match: {}\s*(Determining CMS version \.\.\.(\s*- Found version: (\S+)\s+[VERSION])?)?'


products_match['http']['web-framework'] = {

    'Bootstrap': {
        'wappalyzer': 'Bootstrap',
    },
    'Angular Material': {
        'wappalyzer': 'Angular Material',
    },
    'CakePHP': {
        'wappalyzer': 'CakePHP',
        'wig': [
            WIG_REGEXP.format('CakePHP'),
            WIG_REGEXP2.format('CakePHP'),
        ],
    },
    'CodeIgniter': {
        'wappalyzer': 'CodeIgniter',
    },
    'Django': {
        'wappalyzer': 'Django',
        'wig': [
            WIG_REGEXP.format('Django'),
            WIG_REGEXP2.format('Django'),
        ],
    },
    'Google/Web Toolkit': {
        'wappalyzer': 'Google Web Toolkit',
    },
    'Expressjs/Express': {
        'wappalyzer': 'Express',
    },
    'Laravel': {
        'wappalyzer': 'Laravel',
    },
    'Ruby on Rails': {
        'wappalyzer': 'Ruby on Rails',
    },
    'Symfony': {
        'wappalyzer': 'Symfony',
    },
    'Yiiframework': {
        'wappalyzer': 'Yii',
    },

}