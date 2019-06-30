#!/usr/bin/env bash

clear
git pull
./install-dependencies.sh
python3 jok3r.py toolbox --update-all --fast
python3 jok3r.py toolbox --install-all --fast
python3 jok3r.py toolbox --show-all