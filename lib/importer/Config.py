#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Importer > Config
###
import re

# Matching between original service names and service names used in Jok3r.
# Original service names are the names given by Nmap or importing 
# services (e.g. Shodan).
# Format: { regexp -> service name supported by Jok3r }
#
# For example: 
# - Nmap can use the following names for HTTP services:
# http-alt, http-mgmt, http-proxy, http-wmap, https, https-alt, https-wmap, 
# ssl/http, ssl/https, ssl/ssl
# - Shodan can also use:
# http-simple-new, https-simple-new ...
SERVICE_NAME_MATCHING = {
    '^ajp\S*'          : 'ajp',
    '^ftp\S*'          : 'ftp',
    '^\S*http\S*'      : 'http',
    '^ssl/ssl'         : 'http',
    '^rmiregistry'     : 'java-rmi',
    '^jdwp'            : 'jdwp',
    '^ms-?sql\S*'      : 'mssql',
    '^mysql\S*'        : 'mysql',
    '^oracle\S*'       : 'oracle',
    '^postgre(sql)?'   : 'postgresql',
    '^ms-wbt-server'   : 'rdp',
    '^rdp'             : 'rdp',
    '^microsoft-ds'    : 'smb',
    '^smb'             : 'smb',
    '^smtp\S*'         : 'smtp',
    '^snmp\S*'         : 'snmp',
    '^ssh'             : 'ssh',
    '^telnet\S*'       : 'telnet',
    '^vnc'             : 'vnc',
}

def get_service_name(original_service_name):
    """
    Get service name supported by Jok3r from original service name
    coming from Nmap results or other Importing services (e.g. Shodan)

    :param str original_service_name: Service name as given by Nmap/Shodan
    :return: Service name compliant with Jok3r naming convention if
        one of the pattern in SERVICE_NAME_MATCHING dict is matching,
        otherwise simply retur nthe original service name.
    :rtype: str
    """
    for pattern in SERVICE_NAME_MATCHING:
        if re.match(pattern, original_service_name, re.IGNORECASE):
            return SERVICE_NAME_MATCHING[pattern]

    return original_service_name

