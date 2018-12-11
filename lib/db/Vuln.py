#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Vuln
###
import enum
from sqlalchemy import ForeignKey, Column, Integer, String
from sqlalchemy.orm import relationship

from lib.db.Session import Base


class Vuln(Base):
    __tablename__ = 'vulns'

    id         = Column(Integer, primary_key=True)
    name       = Column(String(255), nullable=False, default='')
    service_id = Column(Integer, ForeignKey('services.id'))

    service    = relationship('Service', back_populates='vulns')


    def __repr__(self):
        return '<Vuln(name="{name}">'.format(name=self.name)
