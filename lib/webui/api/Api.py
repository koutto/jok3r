#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > API > Flask REST Api definition
###
import psutil
import subprocess
from flask_restplus import Api

from lib.core.Config import *
from lib.core.Settings import Settings
from lib.jobmanager.JobManager import JobManager

api = Api(
    version='1.0', 
    title='Jok3r REST API', 
    description='REST API to access Jok3r database'
)

try:
    settings
except NameError:
    settings = Settings()

# Start Job Manager
try:
    jobmanager
except NameError:
    print('DEFINE')
    jobmanager = JobManager(3, 7000)

# Start shell (ttyd)
is_start_shell_running = False
for proc in psutil.process_iter():
    cmdline = proc.cmdline()
    if len(cmdline) == 2:
        if cmdline[1].endswith('start_shell.sh'):
           is_start_shell_running = True

if not is_start_shell_running:
    subprocess.Popen([
        TOOL_BASEPATH + '/lib/webui/shell/start_shell.sh'
    ])

