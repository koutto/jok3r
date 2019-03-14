#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Service
###
import enum
from sqlalchemy import ForeignKey, Column, Integer, String, Text, Boolean
from sqlalchemy.types import Enum
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method

from lib.db.Credential import Credential
from lib.db.Option import Option
from lib.db.Product import Product
from lib.db.Result import Result
from lib.db.Vuln import Vuln
from lib.db.Session import Base


class Protocol(enum.Enum):
    TCP = 1
    UDP = 2


class Service(Base):
    __tablename__ = 'services'

    id           = Column(Integer, primary_key=True)
    name         = Column(String(100), nullable=False, default='')
    port         = Column(Integer, nullable=False)
    protocol     = Column(Enum(Protocol), nullable=False)
    url          = Column(String(3000), nullable=False, default='')
    up           = Column(Boolean, default=True)
    banner       = Column(String(255), nullable=False, default='')
    http_headers = Column(Text, nullable=False, default='')
    #info         = Column(Text)
    comment      = Column(Text, nullable=False, default='')
    host_id      = Column(Integer, ForeignKey('hosts.id'))

    host         = relationship('Host', back_populates='services')
    credentials  = relationship('Credential', order_by=Credential.username, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    options      = relationship('Option', order_by=Option.name, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    products     = relationship('Product', order_by=Product.type, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    results      = relationship('Result', order_by=Result.id, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    vulns        = relationship('Vuln', order_by=Vuln.id, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')


    #------------------------------------------------------------------------------------

    @hybrid_method
    def merge(self, dst):
        """
        Merge with another Service
        :param Service dst: Service to merge with
        """
        if dst.up != self.up:
            self.up = dst.up
        if dst.banner: 
            self.banner = dst.banner
        if dst.http_headers: 
            self.http_headers = dst.http_headers
        if dst.credentials:
            # Update credentials with same username and auth-type
            if self.credentials:    
                for c1 in self.credentials:
                    print(c1)
                    for c2 in dst.credentials:
                        print(c2)
                        if c1.username == c2.username and c1.type == c2.type:
                            c1.password = c2.password
                            dst.credentials.remove(c2)
            # Add new credentials
            for c in dst.credentials:
                c.service_id = self.id
                self.credentials.append(c)
        if dst.options:
            # Update options with same name
            for o in dst.options:
                matching_option = self.get_option(o.name)
                if matching_option:
                    matching_option.value = o.value
                else:
                    self.options.append(o)
                    o.service_id^= self.id
        return


    #------------------------------------------------------------------------------------
    # Getters

    @hybrid_method
    def get_option(self, name):
        """
        Get a specific option related to the service.
        :param str name: Option name to look for
        :return: Specific option
        :rtype: Option|None
        """
        for opt in self.options:
            if opt.name == name.lower():
                return opt
        return None


    @hybrid_method
    def get_product(self, product_type):
        """
        Get product corresponding to given product type.
        :param str product_type: Product type to look for
        :return: Product
        :rtype: Product|None
        """
        for prod in self.products:
            if prod.type == product_type.lower():
                return prod
        return None


    @hybrid_method
    def get_vuln(self, name):
        """
        Get vulnerability matching (exactly) given name.
        :param str name: Name of vulnerability to look for
        :return: Vulnerability
        :rtype: Vuln|None
        """
        for vuln in self.vulns:
            if vuln.name.lower() == name.lower():
                return vuln
        return None


    @hybrid_method
    def get_credential(self, username, auth_type=None):
        """
        Get credentials with given username.
        :param str username: Username to look for
        :param str auth_type: Authentication type (for HTTP service)
        :return: Credential
        :rtype: Credential|None
        """
        for cred in self.credentials:
            if cred.type == auth_type and cred.username == username:
                return cred
        return None


    @hybrid_method
    def get_nb_credentials(self, single_username=False):
        """
        Get total number of credentials for the service.
        :param bool single_username: If True, get the number of single usernames 
            (password unknown). If False, get the number of username/password couples
        :return: Number of selected credentials
        :rtype: int
        """
        nb = 0
        for cred in self.credentials:
            if single_username:
                if cred.username is not None and cred.password is None:
                    nb += 1
            else:
                if cred.username is not None and cred.password is not None:
                    nb += 1
        return nb


    #------------------------------------------------------------------------------------

    def __repr__(self):
        return '<Service(name="{name}", port="{port}", protocol="{protocol}", ' \
            'url="{url}", up="{up}", banner="{banner}", ' \
            'http_headers="{http_headers}", comment="{comment}")>'.format(
                    name         = self.name, 
                    port         = self.port, 
                    protocol     = self.protocol, 
                    url          = self.url,
                    up           = self.up, 
                    banner       = self.banner, 
                    http_headers = self.http_headers,
                    #info         = self.info,
                    comment      = self.comment)
