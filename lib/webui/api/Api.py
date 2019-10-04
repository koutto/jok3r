#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > REST API
###
from flask_restplus import Api
from lib.db.Session import Session


api = Api(version='1.0', 
          title='Jok3r REST API', 
          description='REST API to access Jok3r database')


sqlsession = Session()