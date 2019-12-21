#!/bin/bash

WEB_TTY_BINARY="ttyd_linux.x86_64"

while true
do
	if [[ ! $(ps aux | grep ${WEB_TTY_BINARY} | grep "port 7010") ]]; then
		$(dirname $0)/${WEB_TTY_BINARY} --interface 127.0.0.1 --port 7010 /bin/bash
	fi
	sleep 3
done
