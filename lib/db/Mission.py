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

    #------------------------------------------------------------------------------------
            
    def __repr__(self):
        return '<Mission(name="{name}", comment="{comment}", ' \
            'creation_date="{creation_date}")>'.format(
                name          = self.name,
                comment       = self.comment,
                creation_date = self.creation_date)

