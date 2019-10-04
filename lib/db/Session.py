#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Session
###
import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.ext.declarative

from lib.core.Config import *

engine = sqlalchemy.create_engine('sqlite:///' + DB_FILE)
Session = sqlalchemy.orm.sessionmaker(bind=engine)

