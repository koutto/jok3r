#!/bin/bash

WEB_TTY_PATH="$1/lib/webui/shell/"
WEB_TTY_BINARY="ttyd_linux.x86_64"

while true
do
	if [[ ! $(ps aux | grep ${WEB_TTY_BINARY} | grep $2) ]]; then
		echo "Re-Spawn ttyd binded on worker $2"
		${WEB_TTY_PATH}${WEB_TTY_BINARY} --interface 127.0.0.1 --port $3 tmux attach -t $2
	fi
	sleep 1
done
