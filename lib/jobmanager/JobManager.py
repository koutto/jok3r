#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### JobManager > Job Manager
###
# Monitoring from console:
# $ rqinfo --interval 1
#
import datetime
import os
import psutil
import redis
import subprocess
import time
import threading
from rq import Worker, Queue

from lib.db.Job import Job
from lib.db.Session import Session
from lib.core.Config import *
from lib.output.Logger import logger
from lib.jobmanager.Job import run_job
from lib.utils.ProcessUtils import ProcessUtils


JOB_TIMEOUT = 5 * 3600 # 5 hours
WEB_TTY_PATH = TOOL_BASEPATH + '/lib/webui/shell/'
WEB_TTY_BINARY = 'ttyd_linux.x86_64'


class JobManager:

    def __init__(
        self, 
        nb_workers,
        start_port_ttyd,
    ):
        self.nb_workers = nb_workers
        self.redis = redis.Redis('localhost')
        self.start_port_ttyd = start_port_ttyd
        self.queue = Queue(connection=self.redis, default=JOB_TIMEOUT)

        if not self.start_redis_server():
            return None

        self.start_workers()
        self.bind_workers_to_ttyd()


        def thread_watchdog():
            """Watchdog thread running in background in order to perform regular checks"""
            while True:
                self.check_jobs_status()
                self.check_workers()
                time.sleep(15)

        thread = threading.Thread(target=thread_watchdog)
        thread.start()


    # ------------------------------------------------------------------------------------
    # Redis-server / Workers / Ttyd processes management

    def start_redis_server(self):
        """
        Check if Redis server is running, otherwise try to restart it.

        :return: Redis server status
        :rtype: bool
        """
        try:
            if self.redis.ping():
                logger.info('Redis-server is running')
        except redis.ConnectionError:
            logger.info('Redis-server is not running. Restarting it...')
            p = subprocess.call(['/usr/sbin/service', 'redis-server', 'restart'])
            if p == 0:
                logger.success('Redis-server restarted')
            else:
                logger.error('An error occured while restarting Redis-server !')
                return False
        return True


    def start_workers(self):
        """
        Start all rq workers with their autostart scripts (start_worker) if they
        are not running yet.
        """
        logger.info('Starting {} rq workers in tmux (with auto-restart)...'.format(
            self.nb_workers))
        for i in range(self.nb_workers):
            if self.is_worker_autostart_script_running(i+1):
                logger.info('Autostart worker script "rqworker_{}" already ' \
                    'running'.format(i+1))
            else:
                logger.info('Spawning autostart worker script ' \
                    '"rqworker_{}"...'.format(i+1))
                if self.start_worker('rqworker_{}'.format(i+1)):
                    logger.success('Worker "rqworker_{}" is running and ' \
                        'registered'.format(i+1))
                else:
                    logger.error('Worker "rqworker_{}" is not running or ' \
                        'not registered'.format(i+1))


    def start_worker(self, worker_name):
        """
        Start worker autostart script.

        :param str worker_name: Name of the worker (rqworker_<num>)
        """
        # Make sure to register death on Redis server if there is already
        # a running worker with the provided name
        worker = self.get_worker_by_name(worker_name)
        if worker:
            worker.register_death()
            time.sleep(2)

        subprocess.Popen([
            TOOL_BASEPATH + '/lib/jobmanager/start_worker.sh',
            worker_name
        ])

        time.sleep(2)
        worker = self.get_worker_by_name(worker_name)
        if worker:
            try:
                worker.register_birth()
            except ValueError:
                # ValueError: There exists an active worker named 'rqworker_1' already
                pass
            return True
        else:
            return False        
        # subprocess.Popen([
        #     'tmux',
        #     'new',
        #     '-d',
        #     '-s',
        #     'rqworker_{}'.format(i+1),
        #     'rq',
        #     'worker'
        # ])       


    def check_workers(self):
        """
        Check if rq workers are running, otherwise make sure to restart them (restart
        their autostart script).
        """
        for i in range(self.nb_workers):
            if not self.is_worker_autostart_script_running(i+1):
                logger.info('Autostart worker script for "rqworker_{}" not detected ' \
                    'running. Respawning...'.format(i+1))
                self.start_worker('rqworker_{}'.format(i+1))         


    def is_worker_autostart_script_running(self, worker_id):
        """
        Check if the worker autostart script is running for a given working id.

        :param int worker_id: Worker identifier to check
        """
        for proc in psutil.process_iter():
            cmdline = proc.cmdline()
            if len(cmdline) == 3:
                if cmdline[1].endswith('start_worker.sh') and \
                   cmdline[2] == 'rqworker_{}'.format(worker_id):
                   return True
        return False


    def is_ttyd_autostart_script_running(self, worker_id):
        """
        Check if the worker autostart script is running for a given working id.

        :param int worker_id: Worker identifier to check
        """
        for proc in psutil.process_iter():
            cmdline = proc.cmdline()
            if len(cmdline) == 4:
                if cmdline[1].endswith('start_ttyd.sh') and \
                   cmdline[2] == 'rqworker_{}'.format(worker_id):
                   return True
        return False


    def bind_workers_to_ttyd(self):
        #self.kill_all_ttyd()
        logger.info('Binding rq workers to ttyd...')
        for i in range(self.nb_workers):
            if self.is_ttyd_autostart_script_running(i+1):
                logger.info('Autostart ttyd script for "rqworker_{id}" already ' \
                    'running and available at http://localhost:{port}'.format(
                        id=i+1,
                        port=self.start_port_ttyd+i
                    )
                )
            else:
                logger.info('Starting ttyd available at http://localhost:{port} ' \
                    'binded to "rqworker_{id}"...'.format(
                        port=self.start_port_ttyd+i,
                        id=i+1
                    )
                )
                self.start_ttyd(
                    'rqworker_{}'.format(i+1),
                    self.start_port_ttyd+i
                )


    def start_ttyd(self, worker_name, port):
        """
        Start ttyd autostart script.

        :param str worker_name: Name of the worker (rqworker_<num>)
        :param int port: Binding port
        """
        subprocess.Popen([
            TOOL_BASEPATH + '/lib/jobmanager/start_ttyd.sh',
            worker_name,
            str(port)
        ])
        # subprocess.Popen([
        #     WEB_TTY_PATH + WEB_TTY_BINARY,
        #     '--interface',
        #     '127.0.0.1',
        #     '--port',
        #     str(self.start_port_ttyd+i),
        #     'tmux',
        #     'attach',
        #     '-t',
        #     'rqworker_{}'.format(i+1)
        # ])


    # ------------------------------------------------------------------------------------

    def kill_all_workers(self):
        """
        Kill all workers and autostart scripts.
        ATTENTION: Should not be used in production because when using -9, the rq worker
        process is not unregistered on the Redis server (it is only after several 
        minutes). As a consequence, it is not possible to start a new rq worker with
        a same name.
        """
        subprocess.call(['pkill', '-9', 'start_worker'])
        subprocess.call(['pkill', '-9', 'rq'])
        subprocess.call(['pkill', '-9', 'tmux'])


    def kill_all_ttyd(self):
        """
        Kill all ttyd and autostart scripts.
        """
        subprocess.call(['pkill', '-9', 'start_ttyd'])
        subprocess.call(['pkill', '-9', 'ttyd'])

    # ------------------------------------------------------------------------------------
    # Workers / Jobs Helpers

    def get_job_ids_by_worker(self):
        job_ids_by_workers = dict()
        workers = Worker.all(connection=self.redis)
        for w in workers:
            current_job = w.get_current_job()
            if current_job:
                job_ids_by_workers[w.name] = current_job.args[0]
            else:
                job_ids_by_workers[w.name] = None
        return job_ids_by_workers


    def get_worker_name_for_job_id(self, job_id):
        job_ids_by_workers = self.get_job_ids_by_worker()
        for worker in job_ids_by_workers:
            if job_ids_by_workers[worker] == job_id:
                return worker
        return None


    def get_running_job_ids(self):
        job_ids = list()
        job_ids_by_workers = self.get_job_ids_by_worker()
        for worker in job_ids_by_workers:
            if job_ids_by_workers[worker] is not None:
                job_ids.append(job_ids_by_workers[worker])
        return job_ids


    def get_worker_by_name(self, worker_name):
        workers = Worker.all(connection=self.redis)
        for w in workers:    
            if w.name == worker_name:
                return w
        return None

    def get_job_from_id(self, job_id):
        return Session.query(Job).filter(Job.id == job_id).first()


    def check_jobs_status(self):
        """
        Check if jobs status in database is consistent with real status.
        Update status in database if needed
        """
        # Check if jobs marked as "running" in database are really running or not
        running_jobs = Session.query(Job).filter(Job.status == 'running').all()
        for job in running_jobs:
            if job.id not in self.get_running_job_ids():
                logger.info('Marking job with id {} as aborted...'.format(job.id))
                job.status = 'aborted'
                now = datetime.datetime.now()
                job.end_time = now
                job.duration = (now - job.start_time).seconds
        Session.commit()

        # Make sure that all jobs that are actually running in workers are well marked
        for job_id in self.get_running_job_ids():
            job = self.get_job_from_id(job_id)
            if job.status != 'running':
                logger.info('Marking job with id {} as running...'.format(job.id))
                job.status = 'running'
        Session.commit()
        return 

    # ------------------------------------------------------------------------------------
    # Job operations

    def create_job(
        self, 
        target_service_id, 
        nmap_banner_grabbing=False,
        force_recheck=False,
        fast_mode=True,
        debug_mode=False,
        attack_profile=None,
        checks_selection=None,
        categories_only=None,
        categories_exclude=None,
        wordlist_users=None,
        wordlist_passwords=None
    ):
        """
        Create a new job. At its creation, the job has the status "created", i.e. it
        is not put in the queue automatically (the method queue_job() must be called
        in order to add the job in the queue).
        """
        job = Job(
            attack_profile=attack_profile,
            checks_selection=checks_selection,
            categories_only=categories_only,
            categories_exclude=categories_exclude,
            nmap_banner_grabbing=nmap_banner_grabbing,
            force_recheck=force_recheck,
            debug_mode=debug_mode,
            fast_mode=fast_mode,
            wordlist_users=wordlist_users,
            wordlist_passwords=wordlist_passwords,
            status='created',
            service_id=target_service_id,
        )
        Session.add(job)
        Session.commit()
        return job


    def queue_job(self, job_id):
        """
        Put a job in the queue, ready to be processed by one worker.

        :param int job_id: Job identifier
        :return: Job object 
        :rtype: rq.job.Job|None
        """
        job = self.get_job_from_id(job_id)
        if not job:
            logger.error('Invalid job id {}'.format(job_id))
            return None

        if job.status != 'created':
            logger.error('Job with id={id} cannot be queued because its status ' \
                'is not "created" (job status = "{status}")'.format(
                    id=job.id,
                    status=job.status
                )
            )
            return None

        logger.info('Queuing job with id={}...'.format(job_id))
        job.status = 'queued'
        Session.commit()
        return self.queue.enqueue_call(
            func=run_job, 
            args=(job_id,),
            timeout=JOB_TIMEOUT
        )


    def cancel_job(self, job_id):
        """
        Cancel a job before it is run. Can only be called on a job with status: 
        created or queued.

        :param int job_id: Job identifier
        :return: Status
        :rtype: bool
        """
        job = self.get_job_from_id(job_id)
        if not job:
            logger.error('Invalid job id {}'.format(job_id))
            return False

        if job.status not in ('created', 'queued'):
            logger.error('Job with id={id} cannot be canceled because its status ' \
                'is neither "created" or "queued" (job status = "{status}")'.format(
                    id=job.id,
                    status=job.status
                )
            )
            return False

        logger.info('Canceling job id={}...'.format(job_id))
        job.status = 'canceled'
        Session.commit()
        return True


    def stop_job(self, job_id):
        """
        Stop a running job. The worker process stays untouched to avoid unexpected
        behaviour, but instead the "jok3r.py" process and all its children processes 
        are terminated.

        :param int job_id: Job identifier
        :return: Status
        :rtype: bool
        """
        job = self.get_job_from_id(job_id)
        if not job:
            logger.error('Invalid job id {}'.format(job_id))
            return False

        if job.status != 'running':
            logger.error('Job with id={id} cannot be stopped because its status ' \
                'is not "running" (job status = "{status}")'.format(
                    id=job.id,
                    status=job.status
                )
            )
            return False            

        worker = self.get_worker_by_name(self.get_worker_name_for_job_id(job_id))
        if not worker:
            logger.warning('Cannot stop job with id={id} because there is no ' \
                'worker currently processing this job'.format(id=job_id))
            return False

        logger.info('Stopping job id={}...'.format(job_id))

        # Get pid of "python3 jok3r.py attack ..." command run by worker
        for p in psutil.Process(pid=worker.pid).children(recursive=True):
            try:
                if 'jok3r.py' in p.cmdline() and 'attack' in p.cmdline():
                    # Kill process and all children
                    ProcessUtils.terminate_process_and_children(worker.pid)
            except:
                pass

        # Update job status
        job.status = 'stopped'
        now = datetime.datetime.now()
        job.end_time = now
        job.duration = (now - job.start_time).seconds
        Session.commit()

        return True


    def restart_job(self, job_id):
        """
        Restart a finished/canceled/stopped job.

        :param int job_id: Job identifier
        :return: Status
        :rtype: bool
        """
        job = self.get_job_from_id(job_id)
        if not job:
            logger.error('Invalid job id {}'.format(job_id))
            return False

        if job.status in ('created', 'queued', 'running'):
            logger.error('Job with id={id} cannot be restarted because its status ' \
                'is "{status}")'.format(
                    id=job.id,
                    status=job.status
                )
            )
            return False

        job.status = 'created'
        Session.commit()

        return (self.queue_job(job_id) is not None) 


    def delete_job(self, job_id):
        """
        Delete a finished/canceled/stopped/created job.

        :param int job_id: Job identifier
        :return: Status
        :rtype: bool
        """  
        job = self.get_job_from_id(job_id)
        if not job:
            logger.error('Invalid job id {}'.format(job_id))
            return False

        if job.status in ('queued', 'running'):
            logger.error('Job with id={id} cannot be deleted because its status ' \
                'is "{status}")'.format(
                    id=job.id,
                    status=job.status
                )
            )
            return False

        Session.delete(job)
        Session.commit()
        return True


    # ------------------------------------------------------------------------------------

    def list_workers(self):
        workers = Worker.all(connection=self.redis)
        for w in workers:
            print('Worker {name}'.format(name=w.name))
            print('  -> pid = {pid}'.format(pid=w.pid))
            print('  -> state = {state}'.format(state=w.state))
            if w.get_current_job():
                print('  -> job_id = {job_id}'.format(job_id=w.get_current_job().args[0]))

