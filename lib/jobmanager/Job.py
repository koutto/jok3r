#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
import psutil
import subprocess
import time

from lib.db.Session import Session
from lib.db.Job import Job
from lib.db.Mission import Mission
from lib.db.Host import Host
from lib.db.Service import Service
from lib.output.Logger import logger


def run_job(job_id):
    job = Session.query(Job).filter(Job.id == job_id).first()
    if not job:
        logger.error('Invalid job id {}'.format(job_id))
        return

    # Check status
    if job.status != 'queued':
        logger.info('Job with id={id} has not "queued" status anymore ' \
            '(new status = {status}). Job skipped'.format(
                id=job_id,
                status=job.status
            )
        )
        return

    # Build command line
    cmd  = ['python3', 'jok3r.py', 'attack']
    cmd += ['--mission', '{}'.format(job.service.host.mission.name)]
    cmd += ['--filter', 'service_id={}'.format(job.service_id)]
    cmd += ['--nmap-banner-grab', 'on' if job.nmap_banner_grabbing else 'off']

    if job.attack_profile:
        cmd += ['--profile', job.attack_profile]
    elif job.checks_selection:
        cmd += ['--checks', job.checks_selection]
    elif job.categories_only:
        cmd += ['--cat-only', job.categories_only]
    elif job.categories_exclude:
        cmd += ['--cat-exclude', job.categories_exclude]

    if job.fast_mode:
        cmd += ['--fast']
    if job.force_recheck:
        cmd += ['--recheck']
    if job.debug_mode:
        cmd += ['-d']

    if job.wordlist_users:
        cmd += ['--userlist', job.wordlist_users]
    if job.wordlist_passwords:
        cmd += ['--passlist', job.wordlist_passwords]

    print(cmd)

    # Get current worker name
    # >>> p.cmdline()
    # ['/usr/bin/python3', '/usr/local/bin/rq', 'worker', '--name', 'rqworker_1']
    p = psutil.Process()
    worker_id = p.cmdline()[-1][-1] # <num> in "rqworker_<num>""

    # Update status
    job.status = 'running'
    job.start_time = datetime.datetime.now()
    job.worker_id = int(worker_id)
    Session.commit()

    # Run command
    try:
        returncode = subprocess.call(cmd)

        # Update status and exit code
        if returncode == 0:
            job.status = 'finished_with_success'
            job.exit_code = 0
        else:
            job.status = 'finished_with_error'
            job.exit_code = returncode
    except KeyboardInterrupt:
        job.status = 'aborted'
    now = datetime.datetime.now()
    job.end_time = now
    job.duration = (now - job.start_time).seconds
    Session.commit()

    return
