#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Screenshot
###
import enum
from sqlalchemy import ForeignKey, Column, Integer, String, LargeBinary
from sqlalchemy.orm import relationship

from lib.db.Session import Base


class ScreenStatus(enum.Enum):
    OK          = 1
    SKIPPED     = 2
    TIMEOUT     = 3
    BADSTATUS   = 4
    ERROR       = 5


class Screenshot(Base):
    __tablename__ = 'screenshot'

    id         = Column(Integer, primary_key=True)
    status     = Column(Enum(ScreenStatus), nullable=False)
    image      = Column(LargeBinary)
    thumbnail  = Column(LargeBinary)
    service_id = Column(Integer, ForeignKey('services.id'))

    service    = relationship('Service', back_populates='screenshot')


    #------------------------------------------------------------------------------------
    
    def __repr__(self):
        return '<Screenshot(status="{status}">'.format(status=self.status)
