#!/usr/bin/env bash

./install-dependencies.sh

python3 jok3r.py toolbox --install-all --fast
python3 jok3r.py toolbox --show-all