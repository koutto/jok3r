# -*- coding: utf-8 -*-
###
### Db > Mission
###
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from lib.db.Session import Base
from lib.db.Host import Host


class Mission(Base):
    __tablename__ = 'missions'

    id            = Column(Integer, primary_key=True)
    name          = Column(String(255), nullable=False, default='')
    comment       = Column(String(255), nullable=False, default='')
    creation_date = Column(DateTime, default=func.now())

    hosts         = relationship('Host', order_by=Host.id, back_populates='mission',
                                 cascade='save-update, merge, delete, delete-orphan')

    def __repr__(self):
        return '<Mission(name="{name}", comment="{comment}", creation_date="{creation_date}")>'.format(
                name          = self.name,
                comment       = self.comment,
                creation_date = self.creation_date)