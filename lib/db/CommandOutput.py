# -*- coding: utf-8 -*-
###
### Db > Output
###
from sqlalchemy import ForeignKey, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import relationship

from lib.db.Session import Base


class CommandOutput(Base):
    __tablename__ = 'command_outputs'

    id        = Column(Integer, primary_key=True)
    cmdline   = Column(Text, nullable=False, default='')
    output    = Column(Text, nullable=False, default='')
    result_id = Column(Integer, ForeignKey('results.id'))

    result    = relationship('Result', back_populates='command_outputs')


    def __repr__(self):
        return '<CommandOutput(cmdline="{cmdline}", output="{output}")>'.format(
                cmdline = self.cmdline, 
                output  = self.output)
