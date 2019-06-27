#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Host
###
import ipaddress

from sqlalchemy import ForeignKey, Column, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method
#from sqlalchemy_utils import IPAddressType
from lib.db.IPAddressType import IPAddressType

from lib.db.Session import Base
from lib.db.Service import Service, Protocol


class Host(Base):
    __tablename__ = 'hosts'

    id         = Column(Integer, primary_key=True)
    ip         = Column(IPAddressType, nullable=False, default='')
    hostname   = Column(String(255), nullable=False, default='')
    os         = Column(String(255), nullable=False, default='')
    os_vendor  = Column(String(255), nullable=False, default='')
    os_family  = Column(String(255), nullable=False, default='')
    mac        = Column(String(255), nullable=False, default='')
    vendor     = Column(String(255), nullable=False, default='')
    type       = Column(String(255), nullable=False, default='')
    comment    = Column(Text, nullable=False, default='')
    mission_id = Column(Integer, ForeignKey('missions.id'))

    mission    = relationship('Mission', back_populates='hosts')
    services   = relationship('Service', order_by=Service.port, back_populates='host',
                              cascade='save-update, merge, delete, delete-orphan')


    #------------------------------------------------------------------------------------

    @hybrid_method
    def merge(self, dst):
        """
        Merge with another Host.
        :param Host dst: Host to merge with
        """
        if dst.hostname: self.hostname = dst.hostname
        if dst.os: self.os = dst.os
        if dst.os_vendor: self.os_vendor = dst.os_vendor
        if dst.os_family: self.os_family = dst.os_family
        if dst.mac: self.mac = dst.mac
        if dst.vendor: self.vendor = dst.vendor
        if dst.type: self.type = dst.type
        return


    @hybrid_method
    def is_in_ip_range(self, ip_range):
        """
        Check if IP address is inside a given IP range.
        :param str ip_range: IP range in CIDR notation
            (e.g. 192.168.1.0/24)
        :return: Status
        :rtype: bool
        """
        net = ipaddress.ip_network(ip_range, strict=False)

        # return min(net) <= self.ip <= max(net) # Too slow  
        return net[0] <= self.ip <= net[-1]


    @is_in_ip_range.expression
    def is_in_ip_range(cls, ip_range):
        """
        Check if IP address is inside a given IP range.
        :param str ip_range: IP range in CIDR notation
            (e.g. 192.168.1.0/24)
        :return: Status
        :rtype: bool
        """
        net = ipaddress.ip_network(ip_range, strict=False)
        return cls.ip.between(net[0], net[-1])


    #------------------------------------------------------------------------------------
    # Getters

    @hybrid_method
    def get_nb_services(self, proto=Protocol.TCP):
        """
        Get number of services on the specified protocol referenced for this host.
        :param lib.db.Service.Protocol proto: Protocol (TCP/UDP)
        :return: Number of services for the specified protocol
        :rtype: int
        """
        nb = 0
        for s in self.services:
            if s.protocol == proto:
                nb += 1

        return nb


    @hybrid_method
    def get_nb_credentials(self, single_username=False):
        """
        Get total number of credentials for all services referenced for this host.
        :param bool single_username: If True, get the number of single usernames 
            (password unknown). If False, get the number of username/password couples
        :return: Number of selected credentials
        :rtype: int
        """
        nb = 0
        for s in self.services:
            for cred in s.credentials:
                if single_username:
                    if cred.username is not None and cred.password is None:
                        nb += 1
                else:
                    if cred.username is not None and cred.password is not None:
                        nb += 1
        return nb


    @hybrid_method
    def get_nb_vulns(self):
        """
        Get total number of vulnerabilities for all services referenced for this host.
        :return: Number of selected vulnerabilities
        :rtype: int
        """
        nb = 0
        for s in self.services:
            nb += len(s.vulns)
            
        return nb


    #------------------------------------------------------------------------------------

    def __repr__(self):
        return '<Host(ip="{ip}", hostname="{hostname}", os="{os}", ' \
            'os_vendor="{os_vendor}", os_family="{os_family}", mac="{mac}", ' \
            'vendor="{vendor}", type="{type}", comment="{comment}")>'.format(
                ip        = self.ip, 
                hostname  = self.hostname, 
                os        = self.os, 
                os_vendor = self.os_vendor, 
                os_family = self.os_family,
                mac       = self.mac,
                vendor    = self.vendor,
                type      = self.type,
                comment   = self.comment)
