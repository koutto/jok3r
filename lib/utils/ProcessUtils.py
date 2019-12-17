#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > ProcessUtils
###
import psutil


class ProcessUtils:

    @staticmethod
    def terminate_process_and_children(pid, timeout=3):
        """
        Tries hard to terminate and ultimately kill process and all the children of 
        this process.
        Adapted from: https://psutil.readthedocs.io/en/latest/#terminate-my-children

        :param int pid: Parent process pid
        :param int timeout: Max time (in seconds) to wait for process killing
        """

        def on_terminate(proc):
            try:
                print("process {} terminated with exit code {}".format(
                    proc,
                    proc.returncode
                ))
            except:
                pass

        procs = psutil.Process(pid=pid).children(recursive=True)
        procs.append(psutil.Process(pid=pid))

        # send SIGTERM
        for p in procs:
            try:
                p.terminate()
            except psutil.NoSuchProcess:
                pass
        gone, alive = psutil.wait_procs(procs, timeout=timeout, callback=on_terminate)

        if alive:
            # send SIGKILL
            for p in alive:
                print("process {} survived SIGTERM; trying SIGKILL".format(p))
                try:
                    p.kill()
                except psutil.NoSuchProcess:
                    pass
            gone, alive = psutil.wait_procs(alive, timeout=timeout, callback=on_terminate)
            if alive:
                # give up
                for p in alive:
                    print("process {} survived SIGKILL; giving up".format(p))
