#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > API > Flask REST Api definition
###
from flask_restplus import Api

from lib.core.Settings import Settings
from lib.jobmanager.JobManager import JobManager

api = Api(version='1.0', 
          title='Jok3r REST API', 
          description='REST API to access Jok3r database')

settings = Settings()
jobmanager = JobManager(3, 7000)


