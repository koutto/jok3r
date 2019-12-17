#!/bin/bash

pkill -9 start_worker
pkill -9 start_ttyd
pkill -9 rq
pkill -9 tmux
pkill -9 ttyd