#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# Most common FTP servers from Shodan

products_match['ftp']['ftp-server'] = {

    'Microsoft/ftpd': {
        'nmap-banner': 'Microsoft ftpd(\s+[VERSION])?',
    },
    'GNU/Inetutils': {
        'nmap-banner': 'GNU Inetutils FTPd(\s+[VERSION])?',
    },
    'Proftpd': {
        'nmap-banner': 'ProFTPD(\s+[VERSION])?',
    },
    'Pureftpd': {
        'nmap-banner' 'Pure-FTPd(\s+[VERSION])?',
    },
    'Serv-u': {
        'nmap-banner': 'Serv-U ftpd(\s+[VERSION])?',
    },
    'Vsftpd': {
        'nmap-banner': 'vsftpd(\s+[VERSION])?'
    }


}
