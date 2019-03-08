#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# Examples:
# product: Microsoft IIS httpd version: 6.0 ostype: Windows 
# product: Apache httpd version: 2.2.4 extrainfo: (Unix) DAV/2
# product: Apache httpd version: 2.0.63 extrainfo: DAV/2 hostname

WIG_REGEXP = '- Found platform {} [VERSION]'

products_match['http']['web-server'] = {

    'Apache': {
        'wappalyzer': 'Apache',
        'nmap': 'Apache httpd(\s+[VERSION])?',
        'wig': WIG_REGEXP.format('Apache'),
    },
    'Hiawatha': {
        'wappalyzer': 'Hiawatha',
        'nmap': 'Hiawatha(\s+httpd)?(\s+[VERSION])?',
    },
    'IBM/HTTP Server': {
        'wappalyzer': 'IBM HTTP Server',
        'nmap': 'IBM(\s+ (HTTP Server|httpd))(\s+[VERSION])?',
    },
    'LiteSpeed Web Server': {
        'wappalyzer': 'LiteSpeed',
        'nmap': 'LiteSpeed httpd(\s+[VERSION])?',
    },
    'Microsoft/IIS': {
        'wappalyzer': 'IIS',
        'nmap': 'Microsoft IIS (httpd|WebDAV)(\s+[VERSION])?',
        'wig': WIG_REGEXP.format('IIS'),
    },
    'Mongoose': {
        'nmap': 'Mongoose httpd(\s+[VERSION])?',
    },
    'Monkey Http Daemon': {
        'wappalyzer': 'Monkey HTTP Server',
        'nmap': 'Monkey httpd(\s+[VERSION])?',
    },
    'Nginx': {
        'wappalyzer': 'Nginx',
        'nmap': 'nginx(\s+[VERSION])?',
        'wig': WIG_REGEXP.format('nginx'),
    },
    'Oracle/Http Server': {
        'wappalyzer': 'Oracle HTTP Server',
        'nmap': 'Oracle HTTP Server(\s+(9iAS httpd|Powered by Apache))?(.+\(version [VERSION]\))?',
    },
    'Railo': {
        'clusterd': [
            'Matched [0-9]+ fingerprints for service railo',
            'Railo (Server|Web Administrator|Server Administrator|AJP)\s+\(version [VERSION]\)',
            'Railo (Server|Web Administrator|Server Administrator|AJP)\s+\(version Any\)',
        ],
    },
    'Rejetto/Http File Server': {
        'nmap': 'HttpFileServer httpd(\s+[VERSION])?',
    },
    'Thttpd': {
        'wappalyzer': 'thttpd',
        'nmap': 'thttpd(\s+[VERSION])?',
    },
    'Yaws': {
        'wappalyzer': 'Yaws',
        'nmap': 'Yaws httpd(\s+[VERSION])?',
    },
    'Zeus Web Server': {
        'nmap': 'Zeus httpd(\s+Admin Server)?(\s+[VERSION])?',
    },
}
