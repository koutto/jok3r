#!/bin/bash

while true
do
	tmux has-session -t $1 &> /dev/null
	if [ $? != 0 ]; then
		echo "Re-Spawn rq worker $1"
		tmux new -d -s $1 rq worker --name $1
	fi
	sleep 3
done
