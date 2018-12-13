#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Option
###
import enum
from sqlalchemy import ForeignKey, Column, Integer, String
from sqlalchemy.orm import relationship

from lib.db.Session import Base


# class OptionType(enum.Enum):
#     BOOLEAN = 1
#     LIST    = 2
#     VAR     = 3


class Option(Base):
    __tablename__ = 'options'

    id         = Column(Integer, primary_key=True)
    #type       = Column(Enum(OptionType), nullable=False)
    name       = Column(String(255), nullable=False, default='')
    value      = Column(String(255), nullable=True)
    service_id = Column(Integer, ForeignKey('services.id'))

    service    = relationship('Service', back_populates='options')


    #------------------------------------------------------------------------------------
    
    def __repr__(self):
        return '<Option(name="{name}", value="{value}">'.format(
            name  = self.name, 
            value = self.value)
