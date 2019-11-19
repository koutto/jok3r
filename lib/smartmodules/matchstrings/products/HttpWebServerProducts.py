#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# List of most common web servers: https://en.wikipedia.org/wiki/Comparison_of_web_server_software

# Examples:
# product: Microsoft IIS httpd version: 6.0 ostype: Windows 
# product: Apache httpd version: 2.2.4 extrainfo: (Unix) DAV/2
# product: Apache httpd version: 2.0.63 extrainfo: DAV/2 hostname

WIG_REGEXP = '{}\s*[VERSION]\s*Platform'
WIG_REGEXP2 = '- Found platform {}(\s*[VERSION])?' 

products_match['http']['web-server'] = {
    'Allegrosoft/RomPager': {
        'wappalyzer': 'Allegro RomPager',
    },
    'Amazon/EC2': {
        'wappalyzer': 'Amazon EC2',
    },
    'AOLserver': {
        'wappalyzer': 'AOLserver',
    },
    'Apache': {
        'wappalyzer': 'Apache',
        'banner': 'Apache httpd(\s*[VERSION])?',
        'wig': [
            WIG_REGEXP.format('Apache'),
            WIG_REGEXP2.format('Apache'),
        ],
    },
    'Apache/Traffic Server': {
        'wappalyzer': 'Apache Traffic Server',
    },
    'Artifactory/Web Server': {
        'wappalyzer': 'Artifactory Web Server',
    },
    'BaseHTTP': {
        'wappalyzer': 'BaseHTTP',
    },
    'Boa': {
        'wappalyzer': 'Boa',
    },
    'Caddy': {
        'wappalyzer': 'Caddy',
    },
    'Cherokee': {
        'wappalyzer': 'Cherokee',
    },
    'CompaqHTTPServer': {
        'wappalyzer': 'CompaqHTTPServer',
    },
    'Apache/CouchDB': {
        'wappalyzer': 'CouchDB',
    },
    'Cowboy': {
        'wappalyzer': 'Cowboy',
    },
    'ELOG HTTP': {
        'wappalyzer': 'ELOG HTTP',
    },
    'EmbedThis/Appweb': {
        'wappalyzer': 'EmbedThis Appweb',
    },
    'G-WAN': {
        'wappalyzer': 'G-WAN',
    },
    'EmbedThis/GoAhead': {
        'wappalyzer': 'GoAhead',
    },
    'Google/Web Server': {
        'wappalyzer': 'Google Web Server',
    },
    'Gunicorn/gunicorn': {
        'wappalyzer': 'gunicorn',
    },
    'Hiawatha': {
        'wappalyzer': 'Hiawatha',
        'banner': 'Hiawatha(\s*httpd)?(\s*[VERSION])?',
    },
    'HHVM': {
        'wappalyzer': 'HHVM',
    },
    'HP/ChaiServer': {
        'wappalyzer': 'HP ChaiServer',
    },
    'HP/Compact Server': {
        'wappalyzer': 'HP Compact Server',
    },
    'HP/iLO': {
        'wappalyzer': 'HP iLO',
    },
    'IBM/HTTP Server': {
        'wappalyzer': 'IBM HTTP Server',
        'banner': 'IBM(\s*(HTTP Server|httpd))?(\s*[VERSION])?',
    },
    'IBM/Tivoli Storage Manager': {
        'wappalyzer': 'IBM Tivoli Storage Manager',
    },
    'Indy': {
        'wappalyzer': 'Indy',
    },
    'Intel/Active Management Technology': {
        'wappalyzer': 'Intel Active Management Technology',
    },
    'Kestrel': {
        'wappalyzer': 'Kestrel',
    },
    'libwww-perl-daemon': {
        'wappalyzer': 'libwww-perl-daemon',
    },
    'mini_httpd': {
        'wappalyzer': 'mini_httpd',
    },
    'National Instruments/LabVIEW': {
        'wappalyzer': 'LabVIEW',
    },
    'Lighttpd': {
        'wappalyzer': 'lighttpd',
        'banner': 'lighttpd(\s*[VERSION])?',
    },
    'LiteSpeed Web Server': {
        'wappalyzer': 'LiteSpeed',
        'banner': 'LiteSpeed httpd(\s+[VERSION])?',
    },
    'Logitech/Media Server': {
        'wappalyzer': 'Logitech Media Server',
    },
    'Microsoft/IIS': {
        'wappalyzer': 'IIS',
        'banner': 'Microsoft IIS (httpd|WebDAV)(\s*[VERSION])?',
        'wig': [
            WIG_REGEXP.format('IIS'),
            WIG_REGEXP2.format('IIS'),
        ],
    },
    'Microsoft/HTTPAPI': {
        'wappalyzer': 'Microsoft HTTPAPI',
    },
    'MiniServ': {
        'wappalyzer': 'MiniServ',
    },
    'Mochiweb Project/MochiWeb': {
        'wappalyzer': 'MochiWeb',
    },
    'Mongrel/Mongrel': {
        'wappalyzer': 'Mongrel',
    },
    'Mongoose': {
        'banner': 'Mongoose httpd(\s*[VERSION])?',
    },
    'Monkey Http Daemon': {
        'wappalyzer': 'Monkey HTTP Server',
        'banner': 'Monkey httpd(\s*[VERSION])?',
    },
    'Nginx': {
        'wappalyzer': 'Nginx',
        'banner': 'nginx(\s*[VERSION])?',
        'wig': [
            WIG_REGEXP.format('nginx'),
            WIG_REGEXP2.format('nginx'),
        ],
    },
    'OpenBSD/httpd': {
        'wappalyzer': 'OpenBSD httpd',
    },
    'OpenGSE': {
        'wappalyzer': 'OpenGSE',
    },
    'OpenResty': {
        'wappalyzer': 'OpenResty',
    },
    'Oracle/Http Server': {
        'wappalyzer': 'Oracle HTTP Server',
        'banner': 'Oracle HTTP Server(\s*(9iAS httpd|Powered by Apache))?(.+\(version [VERSION]\))?',
    },
    'Rejetto/Http File Server': {
        'banner': 'HttpFileServer httpd(\s*[VERSION])?',
    },
    'RX Web Server': {
        'wappalyzer': 'RX Web Server',
    },
    'nghttpx - HTTP/2 proxy': {
        'wappalyzer': 'nghttpx - HTTP/2 proxy',
    },
    'SimpleHTTP': {
        'wappalyzer': 'SimpleHTTP',
    },
    'Splunkd': {
        'wappalyzer': 'Splunkd',
    },
    'Starlet': {
        'wappalyzer': 'Starlet',
    },
    'Tengine': {
        'wappalyzer': 'Tengine',
    },
    'Tornadoweb/Tornado': {
        'wappalyzer': 'TornadoServer',
    },
    'Thttpd': {
        'wappalyzer': 'thttpd',
        'banner': 'thttpd(\s*[VERSION])?',
    },
    'TwistedWeb': {
        'wappalyzer': 'TwistedWeb',
    },
    'Warp': {
        'wappalyzer': 'Warp',
    },
    'Yaws': {
        'wappalyzer': 'Yaws',
        'banner': 'Yaws httpd(\s*[VERSION])?',
    },
    'Zeus Web Server': {
        'banner': 'Zeus httpd(\s*Admin Server)?(\s*[VERSION])?',
    },
    'Zend/Server': {
        'wappalyzer': 'Zend',
    },

}
