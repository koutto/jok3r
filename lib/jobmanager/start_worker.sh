#!/bin/bash

while true
do
	#tmux list-sessions
	tmux has-session -t $1 &> /dev/null
	if [ $? != 0 ]; then
		echo "[~] Spawning rq worker $1"

		# If worker with same name is already registered, make sure to
		# unregister it on Redis server
		if [[ $(rq info --by-queue default --only-workers | grep $1) ]]; then
			echo "[~] Unregistering worker with same name $1 on Redis server"
			redis-cli DEL "rq:worker:$1"
			sleep 3
		fi

		tmux new -d -s $1 rq worker --name $1
		sleep 3
		# If error during starting new worker in tmux, probably means that there
		# is a running worker with same which was not displayed by rq info
		# (this behaviour happens sometimes for unknown reason ?)
		tmux has-session -t $1 &> /dev/null
		if [[ $? != 0 ]]; then
			echo "[~] Unable to start worker $1, forcing worker unregistration"
			redis-cli DEL "rq:worker:$1"
			sleep 3
			ps aux | grep "tmux new" | grep $1
			tmux new -d -s $1 rq worker --name $1
			sleep 1
		fi

		#tmux list-sessions
		rq info --by-queue default --only-workers

	else

		# if [[ ! $(rq info --by-queue default --only-workers | grep $1) ]]; then
		# 	echo "[~] Tmux session running for $1 but no corresponding worker registered"
		# 	tmux kill-session -t $1
		# fi
		sleep 1
	fi
	sleep 3
done
