#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Credential
###
from sqlalchemy import ForeignKey, Column, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method

from lib.db.Base import Base


class Credential(Base):
    __tablename__ = 'credentials'

    id         = Column(Integer, primary_key=True)
    type       = Column(String(100))
    username   = Column(String(255), nullable=False, default='')
    # Password can be NULL when only username is set/known
    password   = Column(String(255), nullable=True) 
    comment    = Column(Text, nullable=False, default='')
    command_output_id = Column(Integer, ForeignKey('command_outputs.id'))
    service_id = Column(Integer, ForeignKey('services.id'))

    command_output = relationship('CommandOutput', back_populates='credentials')
    service = relationship('Service', back_populates='credentials')


    #------------------------------------------------------------------------------------

    @hybrid_method
    def clone(self):
        """
        Duplicate the object
        """
        return Credential(
            type=self.type,
            username=self.username,
            password=self.password,
            comment=self.comment,
            command_output_id=None,
            service_id=None)


    #------------------------------------------------------------------------------------

    def __repr__(self):
        return '<Credential(type="{type}", username="{username}", ' \
            'password="{password}", comment="{comment}">'.format(
                type     = self.type, 
                username = self.username, 
                password = self.password,
                comment  = self.comment)
