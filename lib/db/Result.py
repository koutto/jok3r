#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Result
###
from sqlalchemy import ForeignKey, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method

from lib.db.Base import Base
from lib.db.CommandOutput import CommandOutput


class Result(Base):
    __tablename__ = 'results'

    id            = Column(Integer, primary_key=True)
    category      = Column(String(255), nullable=False, default='')
    check         = Column(String(255), nullable=False, default='')
    tool_used     = Column(String(255))
    start_time    = Column(DateTime)
    end_time      = Column(DateTime)
    duration      = Column(Integer)
    service_id    = Column(Integer, ForeignKey('services.id'))

    service = relationship('Service', back_populates='results')
    command_outputs = relationship('CommandOutput', order_by=CommandOutput.id, 
        back_populates='result', cascade='save-update, merge, delete, delete-orphan')


    #------------------------------------------------------------------------------------

    @hybrid_method
    def merge(self, dst):
        """
        Merge with another Result
        :param Result dst: Result to merge with
        """
        for output in dst.command_outputs:
            self.command_outputs.append(output)
        return


    #------------------------------------------------------------------------------------
    
    def __repr__(self):
        return '<Result(category="{category}", ' \
            'check="{check}"), ' \
            'tool_used="{tool_used}", ' \
            'start_time="{start_time}", ' \
            'end_time="{end_time}", ' \
            'duration="{duration}">'.format(
            category=self.category,
            check=self.check,
            tool_used=self.tool_used,
            start_time=self.start_time,
            end_time=self.end_time,
            duration=self.duration)
