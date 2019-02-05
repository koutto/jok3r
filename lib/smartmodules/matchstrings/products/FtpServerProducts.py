#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# Most common FTP servers from Shodan

products_match['ftp']['ftp-server'] = {

    'Microsoft/ftpd': {
        'nmap': 'Microsoft ftpd(\s+[VERSION])?',
    },
    'GNU/Inetutils': {
        'nmap': 'GNU Inetutils FTPd(\s+[VERSION])?',
    },
    'Proftpd': {
        'nmap': 'ProFTPD(\s+[VERSION])?',
    },
    'Pureftpd': {
        'nmap' 'Pure-FTPd(\s+[VERSION])?',
    },
    'Serv-u': {
        'nmap': 'Serv-U ftpd(\s+[VERSION])?',
    },
    'Vsftpd': {
        'nmap': 'vsftpd(\s+[VERSION])?'
    }


}
