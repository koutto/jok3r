#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > IPAddressType
###
import ipaddress

from sqlalchemy import types


class IPAddressType(types.TypeDecorator):
    """
    Inspired from https://sqlalchemy-utils.readthedocs.io/en/latest/
    _modules/sqlalchemy_utils/types/ip_address.html

    Change an IP address in normal representation (string) to an integer 
    representation on the way in and changes them back to string on the
    way out. 
    """

    impl = types.BigInteger

    def process_bind_param(self, value, dialect):
        if value:
            try:
                ip = ipaddress.ip_address(value)
            except:
                return None
            return int(ip)
        else:
            return None

    def process_result_value(self, value, dialect):
        if value:
            try:
                ip = ipaddress.ip_address(value)
            except:
                return None
            return str(ip)
        else:
            return None

