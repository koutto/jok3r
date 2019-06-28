#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Reporter > IconsMapping
###
# Mapping with Material Design icons names
# https://cdn.materialdesignicons.com/3.7.95/


class IconsMapping:
    
    ICONS = {
        'os_family': {
            'Android':      'android',
            'FreeBSD':      'freebsd',
            'iOS':          'ios',
            'Linux':        'linux',
            'Mac OS':       'apple',
            'macOS':        'apple',
            'Windows':      'windows',
        },

        'device_type': {
            'Client':       'desktop-classic',
            'Desktop':      'desktop-mac',
            'Device':       'switch',
            'Firewall':     'security-network',
            'Game console': 'google-controller',
            'Management':   'network-outline',
            'Media':        'television-classic',
            'Misc':         'chip',
            'Mobile':       'cellphone-android',
            'NAS':          'nas',
            'PDA':          'cellphone',
            'Power device': 'power-plug',
            'Print server': 'printer-settings',
            'Printer':      'printer',
            'Proxy server': 'directions-fork',
            'Server':       'desktop-tower', #'server',
            'VoIP':         'phone-voip',
            'Webcam':       'webcam',
        },

        'category': {
            'recon':        'magnify',
            'vulnlookup':   'search-web',
            'defaultcreds': 'key-variant',
            'vulnscan':     'radar',
            'exploit':      'rocket',
            'bruteforce':   'hammer',
            'discovery':    'sitemap',
            'postexploit':  'account-key',
        },

        'service': {
            'ajp':          'webhook',
            'ftp':          'file-tree',
            'http':         'web',
            'java-rmi':     'language-java',
            'jdwp':         'language-java',
            'mssql':        'database',
            'mysql':        'database',
            'oracle':       'database',
            'postgresql':   'database',
            'rdp':          'remote-desktop',
            'smb':          'folder-network',
            'smtp':         'email-outline',
            'snmp':         'clipboard-pulse-outline',
            'ssh':          'console-network',
            'telnet':       'console-network',
            'vnc':          'remote-desktop',
        }
    }

    @staticmethod
    def get_icon(icon_type, value, default=''):
        if icon_type not in IconsMapping.ICONS:
            return default

        return IconsMapping.ICONS[icon_type].get(value, default)


    @staticmethod
    def get_icon_html(icon_type, value, default=''):
        icon = IconsMapping.get_icon(icon_type, value, default)
        if icon:
            return '<span class="mdi mdi-{}"></span> '.format(icon)
        else:
            return ''