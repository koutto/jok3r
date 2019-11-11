#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Service
###
import enum
from sqlalchemy import ForeignKey, Column, Integer, String, Text, Boolean
#from sqlalchemy.types import Enum
import sqlalchemy.types
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method

from lib.core.Config import *
from lib.db.Credential import Credential
from lib.db.Option import Option
from lib.db.Product import Product
from lib.db.Result import Result
from lib.db.Vuln import Vuln
from lib.db.Base import Base


class Protocol(enum.Enum):
    TCP = 1
    UDP = 2


class Service(Base):
    __tablename__ = 'services'

    id            = Column(Integer, primary_key=True)
    # Service name as used in Jok3r
    name          = Column(String(100), nullable=False, default='')
    # Original service name as given by Nmap/Shodan
    name_original = Column(String(100), nullable=False, default='')
    port          = Column(Integer, nullable=False)
    protocol      = Column(sqlalchemy.types.Enum(Protocol), nullable=False)
    url           = Column(String(3000), nullable=False, default='')
    up            = Column(Boolean, default=True)
    banner        = Column(String(255), nullable=False, default='')
    html_title    = Column(String(255), nullable=False, default='')
    http_headers  = Column(Text, nullable=False, default='')
    web_technos   = Column(Text, nullable=False, default='')
    comment       = Column(Text, nullable=False, default='')
    host_id       = Column(Integer, ForeignKey('hosts.id'))

    host          = relationship('Host', back_populates='services')
    credentials   = relationship('Credential', order_by=Credential.username, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    options       = relationship('Option', order_by=Option.name, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    products      = relationship('Product', order_by=Product.type, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    results       = relationship('Result', order_by=Result.id, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    vulns         = relationship('Vuln', order_by=Vuln.id, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')
    screenshot    = relationship('Screenshot', uselist=False, 
        back_populates='service', cascade='save-update, merge, delete, delete-orphan')


    #------------------------------------------------------------------------------------

    @hybrid_method
    def merge(self, dst):
        """
        Merge with another Service
        matching_service.merge(new_service)

        :param Service dst: Service that we want to merge with (this is typîcally
            a new service that we want to add but there is already a matching 
            service in db, so we will not add this new service but update the matching
            one)
        """
        if dst.up != self.up:
            self.up = dst.up

        if dst.banner: 
            self.banner = dst.banner

        if dst.html_title:
            self.html_title = dst.html_title

        if dst.http_headers: 
            self.http_headers = dst.http_headers

        if dst.web_technos:
            self.web_technos = dst.web_technos

        # Update credentials with same username and auth-type
        if dst.credentials:
            for c in dst.credentials:
                self.add_credential(c)

        # Update options with same name
        if dst.options:
            for o in dst.options:
                self.add_option(o)

        # Update products
        if dst.products:
            for p in dst.products:
                self.add_product(p)

        return


    #------------------------------------------------------------------------------------

    @hybrid_method
    def add_credential(self, cred):
        """
        Add credential to the service.
        Make sure to not add twice the same credential.
        Update password if necessary

        :param Credential cred: Credential object to add
        """
        matching_cred = self.get_credential(cred.username, cred.type)
        if matching_cred:
            matching_cred.password = cred.password
        else:
            self.credentials.append(cred)
            cred.service_id = self.id


    @hybrid_method
    def add_option(self, option):
        """
        Add option to the service.
        Make sure to not add twice the same option.
        Update value if necessary

        :param Option option: Option object to add
        """
        matching_option = self.get_option(option.name)
        if matching_option:
            matching_option.value = option.value
        else:
            self.options.append(option)
            option.service_id = self.id


    @hybrid_method
    def add_product(self, product):
        """
        Add product to the service.
        Make sure to not add twice the same product.
        Update value if necessary

        :param Product product: Product object to add
        """
        matching_product = self.get_product(product.type)
        if matching_product:
            matching_product.name = product.name
            matching_product.version = product.version
        else:
            self.products.append(product)
            product.service_id = self.id


    #------------------------------------------------------------------------------------
    @hybrid_method
    def is_encrypted(self):
        """
        Indicates if the service is encrypted (i.e. is using SSL/TLS)
        :return: True if SSL/TLS is used
        :rtype: bool
        """
        for opt in self.options:
            if opt.name in OPTIONS_ENCRYTPED_PROTO:
                return True
        return False


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
    def get_options_no_encrypt(self):
        """
        Get all options related to the service, except options related to 
        encryption (https, ftps...)
        :return: List of Specific options
        :rtype: list(Option)
        """
        res = list()
        for opt in self.options:
            if opt.name not in OPTIONS_ENCRYTPED_PROTO:
                res.append(opt)
        return res


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


    @hybrid_method
    def get_checks_categories(self):
        """
        Get list of categories of checks that have been partially or fully run for the
        service.
        Note: If only one single check in a category (e.g. recon) has been run for the
        service, it is returned.
        :return: List of categories of checks
        :rtype: list({'name': str, 'count': int)
        """
        categories = list()
        for res in self.results:
            found = False
            for cat in categories:
                if res.category == cat['name']:
                    cat['count'] += 1
                    found = True
                    break
            if not found:
                categories.append({
                    'name': res.category,
                    'count': 1,
                })

        return categories


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
