#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Product
###
import enum
from sqlalchemy import ForeignKey, Column, Integer, String
from sqlalchemy.orm import relationship

from lib.db.Session import Base


class Product(Base):
    __tablename__ = 'products'

    id         = Column(Integer, primary_key=True)
    type       = Column(String(100), nullable=False, default='')
    name       = Column(String(255), nullable=False, default='')
    version    = Column(String(100), nullable=False, default='')
    service_id = Column(Integer, ForeignKey('services.id'))

    service    = relationship('Service', back_populates='products')


    #------------------------------------------------------------------------------------
    
    def __repr__(self):
        return '<Product(type="{type}", name="{name}", version="{version}">'.format(
            type    = self.type, 
            name    = self.name, 
            version = self.version)
