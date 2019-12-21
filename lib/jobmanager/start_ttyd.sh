#!/bin/bash

WEB_TTY_BINARY="ttyd_linux.x86_64"

while true
do
	if [[ ! $(ps aux | grep ${WEB_TTY_BINARY} | grep $1) ]]; then
		echo "Spawn ttyd binded on worker $2"
		$(dirname $0)/../webui/shell/${WEB_TTY_BINARY} --interface 127.0.0.1 --port $2 tmux attach -t $1
	fi
	sleep 1
done
