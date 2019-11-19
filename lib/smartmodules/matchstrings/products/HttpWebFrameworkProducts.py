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
    'Akka HTTP': {
        'wappalyzer': 'Akka HTTP',
    },
    'Amber': {
        'wappalyzer': 'Amber',
    },
    'AngularDart': {
        'wappalyzer': 'AngularDart',
    },
    'Apache/Wicket': {
        'wappalyzer': 'Apache Wicket',
    },
    'Banshee-project/Banshee': {
        'wappalyzer': 'Banshee',
    },
    'Blade': {
        'wappalyzer': 'Blade',
    },
    'Blazor': {
        'wappalyzer': 'Blazor',
    },
    'Bonfire': {
        'wappalyzer': 'Bonfire',
    },
    'CherryPy': {
        'wappalyzer': 'CherryPy',
    },
    'Sencha/Connect': {
        'wappalyzer': 'Connect',
    },
    'Dancer': {
        'wappalyzer': 'Dancer',
    },
    'Expressjs/Express': {
        'wappalyzer': 'Express',
    },
    'Fat-Free Framework': {
        'wappalyzer': 'Fat-Free Framework',
    },
    'Flask': {
        'wappalyzer': 'Flask',
    },
    'Includable': {
        'wappalyzer': 'Includable',
    },
    'Ionic': {
        'wappalyzer': 'Ionic',
    },
    'Java Servlet': {
        'wappalyzer': 'Java Servlet',
    },
    'JavaServer Faces': {
        'wappalyzer': 'JavaServer Faces',
    },
    'JavaServer Pages': {
        'wappalyzer': 'JavaServer Pages',
    },
    'Kemal': {
        'wappalyzer': 'Kemal',
    },
    'Koa': {
        'wappalyzer': 'Koa',
    },
    'Koala Framework': {
        'wappalyzer': 'Koala Framework',
    },
    'Kohanaframework/Kohana': {
        'wappalyzer': 'Kohana',
    },
    'Laravel/Laravel': {
        'wappalyzer': 'Laravel',
    },
    'Liftweb/Lift': {
        'wappalyzer': 'Lift',
    },
    'Lighty': {
        'wappalyzer': 'Lighty',
    },
    'Mojolicious': {
        'wappalyzer': 'Mojolicious',
    },
    'Mono Project/Mono': {
        'wappalyzer': 'Mono',
    },
    'Neos Flow': {
        'wappalyzer': 'Neos Flow',
    },
    'Nette Framework': {
        'wappalyzer': 'Nette Framework',
    },
    'Playframework/Play Framework': {
        'wappalyzer': 'Play',
    },
    'Revel': {
        'wappalyzer': 'Revel',
    },
    'Sapper': {
        'wappalyzer': 'Sapper',
    },
    'Phoenixframework/Phoenix': {
        'wappalyzer': 'Phoenix',
    },
    'Shiny': {
        'wappalyzer': 'Shiny',
    },
    'Snap': {
        'wappalyzer': 'Snap',
    },
    'Swiftlet': {
        'wappalyzer': 'Swiftlet',
    },
    'ThinkPHP': {
        'wappalyzer': 'ThinkPHP',
    },
    'TwistPHP': {
        'wappalyzer': 'TwistPHP',
    },
    'Vaadin': {
        'wappalyzer': 'Vaadin',
    },
    'Web2py': {
        'wappalyzer': 'Web2py',
    },
    'Xeora': {
        'wappalyzer': 'Xeora',
    },
    'Zkoss/Zk Framework': {
        'wappalyzer': 'ZK',
    },
    'actionhero.js': {
        'wappalyzer': 'actionhero.js',
    },

}