#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import sys
import time
from lib.jobmanager.JobManager import JobManager
from lib.jobmanager.Job import *



jobmanager = JobManager(3, 7000)
if jobmanager is None:
    sys.exit(1)

jobmanager.create_job(1, force_recheck=True)
jobmanager.create_job(2, force_recheck=True)
jobmanager.create_job(1, force_recheck=True)
jobmanager.cancel_job(1)

jobmanager.queue_job(1)
time.sleep(10)
print(jobmanager.get_job_ids_by_worker())
jobmanager.queue_job(2)
print(jobmanager.get_job_ids_by_worker())
time.sleep(10)
print(jobmanager.get_job_ids_by_worker())
jobmanager.queue_job(3)
print(jobmanager.get_job_ids_by_worker())
time.sleep(10)
print(jobmanager.get_job_ids_by_worker())
#jobmanager.list_workers()

# jobmanager.kill_all_workers()
# jobmanager.kill_all_ttyd()

time.sleep(20)
jobmanager.stop_job(1)
print(jobmanager.get_job_ids_by_worker())
time.sleep(10)
print(jobmanager.get_job_ids_by_worker())
# jobmanager.stop_job(2)
# jobmanager.stop_job(3)