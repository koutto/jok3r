#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Reporter > IconsMapping
###
# Mapping with Material Design icons names
# https://cdn.materialdesignicons.com/3.7.95/


class IconsMapping:
    
    OS_FAMILY = {
        'Android': 'android',
        'FreeBSD': 'freebsd',
        'iOS': 'ios',
        'Linux': 'linux',
        'Mac OS': 'apple',
        'macOS': 'apple',
        'Windows': 'windows',
    }

    DEVICE_TYPE = {
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
    }

    CATEGORY = {
        'recon': 'magnify',
        'vulnlookup': 'search-web',
        'defaultcreds': 'key-variant',
        'vulnscan': 'radar',
        'exploit': 'rocket',
        'bruteforce': 'hammer',
        'discovery': 'sitemap',
        'postexploit': 'account-key',
    }