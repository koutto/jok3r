#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Command Output
###
from sqlalchemy import ForeignKey, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import relationship

from lib.db.Base import Base
from lib.db.Credential import Credential
from lib.db.Vuln import Vuln

class CommandOutput(Base):
    __tablename__ = 'command_outputs'

    id        = Column(Integer, primary_key=True)
    cmdline   = Column(Text, nullable=False, default='')
    output    = Column(Text, nullable=False, default='')
    outputraw = Column(Text, nullable=False, default='')
    result_id = Column(Integer, ForeignKey('results.id'))

    result = relationship('Result', back_populates='command_outputs')
    credentials = relationship('Credential', order_by=Credential.id, 
        back_populates='result')
    vulns = relationship('Vuln', order_by=Vuln.id, 
        back_populates='result')


    #------------------------------------------------------------------------------------
    
    def __repr__(self):
        return '<CommandOutput(cmdline="{cmdline}", output="{output}")>'.format(
            cmdline = self.cmdline, 
            output  = self.output)
