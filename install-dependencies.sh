#!/usr/bin/env bash

print_title() {
        BOLD=$(tput bold ; tput setaf 2)
        NORMAL=$(tput sgr0)
        echo "${BOLD} $1 ${NORMAL}"
}


print_title "[~] Install Metasploit ..."
apt-get install -y metasploit-framework 

print_title "[~] Install Nmap ..."
apt-get install -y nmap 

print_title "[~] Install tcpdump ..."
apt-get install -y tcpdump

print_title "[~] Install NodeJS ..."
curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
sudo apt-get install -y --ignore-missing nodejs npm

print_title "[~] Install Python 2.7 + 3 and useful related packages"
sudo apt-get install -y --ignore-missing python python2.7 python3 python-pip python3-pip python-dev python3-dev python-setuptools python3-setuptools
sudo apt-get install -y --ignore-missing python-ipy python-nmap
sudo pip3 uninstall -y psycopg2
sudo pip3 install psycopg2-binary

print_title "[~] Install Ruby latest + old version (2.3) required for some tools"
sudo apt-get install -y --ignore-missing ruby ruby-dev
curl -sSL https://get.rvm.io | bash
source /etc/profile.d/rvm.sh
echo "source /etc/profile.d/rvm.sh" >> ~/.bashrc
rvm install ruby-2.3
rvm install ruby-2.5
rvm --default use 2.5
gem install ffi

print_title "[~] Install Perl and useful related packages"
sudo apt-get install -y --ignore-missing perl libwhisker2-perl libwww-perl

print_title "[~] Install PHP"
sudo apt-get install -y --ignore-missing php

print_title "[~] Install Java"
sudo apt-get install -y --ignore-missing default-jdk

print_title "[~] Install other required packages"
sudo apt-get install -y --ignore-missing zlib1g-dev libcurl4-openssl-dev liblzma-dev libxml2 libxml2-dev libxslt1-dev build-essential libgmp-dev 
sudo apt-get install -y --ignore-missing gcc make automake patch libssl-dev locate

print_title "[~] Install Python3 libraries required by Jok3r"
sudo pip3 install -r requirements.txt