#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# Most common FTP servers from Shodan

products_match['ftp']['ftp-server'] = {

    'Microsoft/ftpd': {
        'banner': 'Microsoft ftpd(\s+[VERSION])?',
    },
    'GNU/Inetutils': {
        'banner': 'GNU Inetutils FTPd(\s+[VERSION])?',
    },
    'Proftpd': {
        'banner': 'ProFTPD(\s+[VERSION])?',
    },
    'Pureftpd': {
        'banner': 'Pure-FTPd(\s+[VERSION])?',
    },
    'Serv-u': {
        'banner': 'Serv-U ftpd(\s+[VERSION])?',
    },
    'Vsftpd': {
        'banner': 'vsftpd(\s+[VERSION])?',
    },


}
