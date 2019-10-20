#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Mission
###
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method
from sqlalchemy.sql import func

from lib.db.Base import Base
from lib.db.Host import Host


class Mission(Base):
    __tablename__ = 'missions'

    id            = Column(Integer, primary_key=True)
    name          = Column(String(255), nullable=False, default='')
    comment       = Column(String(255), nullable=False, default='')
    creation_date = Column(DateTime, default=func.now())

    hosts         = relationship('Host', order_by=Host.id, back_populates='mission',
        cascade='save-update, merge, delete, delete-orphan')


    #------------------------------------------------------------------------------------

    @hybrid_method
    def get_nb_services(self):
        """Return the total number of services inside the mission scope"""
        nb = 0
        for host in self.hosts:
            nb += len(host.services)
        return nb


    @hybrid_method
    def get_nb_credentials(self, single_username=False):
        """
        Get total number of credentials for all services referenced for this mission.
        :param bool single_username: If True, get the number of single usernames 
            (password unknown). If False, get the number of username/password couples
        :return: Number of selected credentials
        :rtype: int
        """
        nb = 0
        for h in self.hosts:
            nb += h.get_nb_credentials(single_username)
        return nb


    @hybrid_method
    def get_nb_products(self):
        """
        Get total number of detected products for all services referenced for 
        this mission.
        :return: Number of detected products
        :rtype: int
        """
        nb = 0
        for h in self.hosts:
            nb += h.get_nb_products()
        return nb


    @hybrid_method
    def get_nb_vulns(self):
        """
        Get total number of detected vulns for all services referenced for 
        this mission.
        :return: Number of detected vulns
        :rtype: int
        """
        nb = 0
        for h in self.hosts:
            nb += h.get_nb_vulns()
        return nb

    #------------------------------------------------------------------------------------
            
    def __repr__(self):
        return '<Mission(name="{name}", comment="{comment}", ' \
            'creation_date="{creation_date}")>'.format(
                name          = self.name,
                comment       = self.comment,
                creation_date = self.creation_date)

