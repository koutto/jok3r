#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Vuln
###
import enum
from sqlalchemy import ForeignKey, Column, Boolean, Integer, String, Float, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method

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
    command_output_id = Column(Integer, ForeignKey('command_outputs.id'))
    service_id        = Column(Integer, ForeignKey('services.id'))

    command_output = relationship('CommandOutput', back_populates='vulns')
    service = relationship('Service', back_populates='vulns')


    #------------------------------------------------------------------------------------

    @hybrid_method
    def merge(self, dst):
        """
        Merge with another Vuln
        matching_vuln.merge(new_vuln)
        This is actually used if the new Vuln has more info than the existing one, 
        in order to update the missing fields.

        :param Vuln dst: Vuln that we want to merge with (this is typîcally
            a new vuln that we want to add but there is already a matching 
            vuln in db, so we will not add this new vuln but update the matching
            one)
        """
        if dst.description and dst.description != self.description:
            self.description = dst.description

        if dst.location and not self.location: 
            self.location = dst.location

        if dst.reference and not self.reference:
            # Reference should not be different
            self.reference = dst.reference

        if dst.score and not self.score:
            # Score should not be different
            self.score = dst.score

        if dst.link and not self.link:
            # Link should not be different
            self.link = dst.link

        if dst.exploit_available and not self.exploit_available:
            self.exploit_available = dst.exploit_available

        if dst.exploited and not self.exploited:
            self.exploited = dst.exploited

        return


    #------------------------------------------------------------------------------------


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
