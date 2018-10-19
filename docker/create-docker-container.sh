#!/usr/bin/env bash

sudo apt-get install docker
sudo service docker start
sudo docker build -t jok3r-image .
sudo docker run --name jok3r-container -i -t jok3r-image