#!/usr/bin/env bash

print_title() {
        BOLD=$(tput bold ; tput setaf 2)
        NORMAL=$(tput sgr0)
        echo "${BOLD} $1 ${NORMAL}"
}

# if ! [ -x "$(command -v git)" ]; then
#   echo 'Error: git is not installed.' >&2
#   exit 1
# fi

if ! [ -x "$(command -v msfconsole)" ]; then
    print_title "[~] Install Metasploit ..."
    apt-get install -y metasploit-framework 
else
    print_title "[+] Metasploit is already installed"
fi

if ! [ -x "$(command -v nmap)" ]; then
    print_title "[~] Install Nmap ..."
    apt-get install -y nmap 
else
    print_title "[+] Nmap is already installed"
fi

if ! [ -x "$(command -v tcpdump)" ]; then
    print_title "[~] Install tcpdump ..."
    apt-get install -y tcpdump
else
    print_title "[+] tcpdump is already installed"
fi

if ! [ -x "$(command -v npm)" ]; then
    print_title "[~] Install NodeJS ..."
    curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    print_title "[+] NodeJS is already installed"
fi    

print_title "[~] Install Python 2.7 + 3 and useful related packages (if missing)"
sudo apt-get install -y --ignore-missing python python2.7 python3 python-pip python3-pip python-dev python3-dev python-setuptools python3-setuptools
sudo apt-get install -y --ignore-missing python-ipy python-nmap python3-pymysql
sudo pip3 uninstall -y psycopg2
sudo pip3 install psycopg2-binary

if ! [ -x "$(command -v jython)" ]; then
    print_title "[~] Install Jython"
    sudo apt-get install -y jython
else
    print_title "[+] Jython is already installed"
fi


if ! [ -x "$(command -v rvm)" ]; then
    print_title "[~] Install Ruby latest + old version (2.3) required for some tools"
    #sudo apt-get install -y --ignore-missing ruby ruby-dev
    curl -sSL https://get.rvm.io | bash
    source /etc/profile.d/rvm.sh
    echo "source /etc/profile.d/rvm.sh" >> ~/.bashrc
    rvm install ruby-2.3
    rvm install ruby-2.5
    rvm --default use 2.5
    gem install ffi
else
    print_title "[+] Ruby is already installed"
fi

if ! [ -x "$(command -v perl)" ]; then
    print_title "[~] Install Perl and useful related packages"
    sudo apt-get install -y --ignore-missing perl libwhisker2-perl libwww-perl
else
    print_title "[+] Perl is already installed"
fi

if ! [ -x "$(command -v php)" ]; then
    print_title "[~] Install PHP"
    sudo apt-get install -y --ignore-missing php
else
    print_title "[+] PHP is already installed"
fi

if ! [ -x "$(command -v java)" ]; then
    print_title "[~] Install Java"
    sudo apt-get install -y --ignore-missing default-jdk
else
    print_title "[+] Java is already installed"
fi

print_title "[~] Install other required packages (if missing)"
sudo apt-get install -y --ignore-missing zlib1g-dev libcurl4-openssl-dev liblzma-dev libxml2 libxml2-dev libxslt1-dev build-essential libgmp-dev 
sudo apt-get install -y --ignore-missing gcc make automake patch libssl-dev locate libffi-dev
sudo apt-get install -y --ignore-missing smbclient

print_title "[~] Install Python3 libraries required by Jok3r (if missing)"
sudo pip3 install -r requirements.txt