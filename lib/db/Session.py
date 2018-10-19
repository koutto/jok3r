# -*- coding: utf-8 -*-
###
### Db > Base
###
import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.ext.declarative

from lib.core.Config import *


Base = sqlalchemy.ext.declarative.declarative_base()
engine = sqlalchemy.create_engine('sqlite:///' + DB_FILE)
Session = sqlalchemy.orm.sessionmaker(bind=engine)

