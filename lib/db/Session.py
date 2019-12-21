#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Session
###
import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.ext.declarative

from lib.core.Config import *


engine = sqlalchemy.create_engine(DB_STRING)
#Session = sqlalchemy.orm.sessionmaker(bind=engine)

# Thread-safe sessions
# https://docs.sqlalchemy.org/en/13/orm/contextual.html
# https://stackoverflow.com/questions/34009296/using-sqlalchemy-session-from-flask-raises-sqlite-objects-created-in-a-thread-c
session_factory = sqlalchemy.orm.sessionmaker(bind=engine)
Session = sqlalchemy.orm.scoped_session(session_factory)

