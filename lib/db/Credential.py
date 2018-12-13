#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Credential
###
from sqlalchemy import ForeignKey, Column, Integer, String, Text
from sqlalchemy.orm import relationship

from lib.db.Session import Base


class Credential(Base):
    __tablename__ = 'credentials'

    id         = Column(Integer, primary_key=True)
    type       = Column(String(100))
    username   = Column(String(255), nullable=False, default='')
    # Password can be NULL when only username is set/known
    password   = Column(String(255), nullable=True) 
    comment    = Column(Text, nullable=False, default='')
    service_id = Column(Integer, ForeignKey('services.id'))

    service    = relationship('Service', back_populates='credentials')


    #------------------------------------------------------------------------------------

    def __repr__(self):
        return '<Credential(type="{type}", username="{username}", ' \
            'password="{password}", comment="{comment}">'.format(
                type     = self.type, 
                username = self.username, 
                password = self.password,
                comment  = self.comment)
