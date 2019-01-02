#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Host
###
import ipaddress

from sqlalchemy import ForeignKey, Column, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method
from sqlalchemy_utils import IPAddressType

from lib.db.Session import Base
from lib.db.Service import Service


class Host(Base):
    __tablename__ = 'hosts'

    id         = Column(Integer, primary_key=True)
    ip         = Column(IPAddressType, nullable=False, default='')
    hostname   = Column(String(255), nullable=False, default='')
    os         = Column(String(255), nullable=False, default='')
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
        return min(net) <= self.ip <= max(net)  


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
        return cls.ip.between(min(net), max(net))


    #------------------------------------------------------------------------------------

    def __repr__(self):
        return '<Host(ip="{ip}", hostname="{hostname}", os="{os}", ' \
            'comment="{comment}")>'.format(
                ip       = self.ip, 
                hostname = self.hostname, 
                os       = self.os, 
                comment  = self.comment)
