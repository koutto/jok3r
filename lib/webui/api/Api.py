#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > API > Flask REST Api definition
###
from flask_restplus import Api
from lib.core.Settings import Settings

api = Api(version='1.0', 
          title='Jok3r REST API', 
          description='REST API to access Jok3r database')

settings = Settings()
