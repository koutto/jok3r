#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Vuln
###
import enum
from sqlalchemy import ForeignKey, Column, Boolean, Integer, String, Float, Text
from sqlalchemy.orm import relationship

from lib.db.Base import Base


class Vuln(Base):
    __tablename__ = 'vulns'

    id                = Column(Integer, primary_key=True)
    name              = Column(Text, nullable=False, default='')
    description       = Column(Text, default='')
    location          = Column(String(400))
    reference         = Column(String(255))
    score             = Column(Float)
    link              = Column(String(400))
    exploit_available = Column(Boolean, default=False)
    exploited         = Column(Boolean, default=False)
    result_id         = Column(Integer, ForeignKey('results.id'))
    service_id        = Column(Integer, ForeignKey('services.id'))

    result = relationship('Result', back_populates='vulns')
    service = relationship('Service', back_populates='vulns')


    def __repr__(self):
        return '<Vuln(name="{name}", ' \
            'description="{description}", ' \
            'location="{location}", ' \
            'reference="{reference}", ' \
            'score="{score}", ' \
            'link="{link}", ' \
            'exploit_available="{exploit_available}", ' \
            'exploited="{exploited}">'.format(
                name=self.name,
                description=self.description,
                location=self.location,
                reference=self.reference,
                score=self.score,
                link=self.link,
                exploit_available=self.exploit_available,
                exploited=self.exploited)
