#!/usr/bin/env bash

print_title() {
        BOLD=$(tput bold ; tput setaf 2)
        NORMAL=$(tput sgr0)
        echo "${BOLD} $1 ${NORMAL}"
}

print_delimiter() {
    echo
    echo "-------------------------------------------------------------------------------"
    echo
}


echo
echo
print_title "=============================="
print_title "Install dependencies for Jok3r"
print_title "=============================="
echo

if ! [ -x "$(command -v git)" ]; then
    print_title "[~] Install git ..."
    apt-get install -y git
else
    print_title "[+] Git is already installed"
fi
print_delimiter

if ! [ -x "$(command -v msfconsole)" ]; then
    print_title "[~] Install Metasploit ..."
    apt-get install -y metasploit-framework 
else
    print_title "[+] Metasploit is already installed"
fi
print_delimiter

if ! [ -x "$(command -v nmap)" ]; then
    print_title "[~] Install Nmap ..."
    apt-get install -y nmap 
else
    print_title "[+] Nmap is already installed"
fi
print_delimiter

if ! [ -x "$(command -v tcpdump)" ]; then
    print_title "[~] Install tcpdump ..."
    apt-get install -y tcpdump
else
    print_title "[+] tcpdump is already installed"
fi
print_delimiter

if ! [ -x "$(command -v npm)" ]; then
    print_title "[~] Install NodeJS ..."
    curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    print_title "[+] NodeJS is already installed"
fi
print_delimiter   

print_title "[~] Install Python 2.7 + 3 and useful related packages (if missing)"
sudo apt-get install -y --ignore-missing python python2.7 python3 python-pip python3-pip 
sudo apt-get install -y --ignore-missing python-dev python3-dev python-setuptools 
sudo apt-get install -y --ignore-missing python3-setuptools python3-distutils
sudo apt-get install -y --ignore-missing python-ipy python-nmap python3-pymysql
sudo pip3 uninstall -y psycopg2
sudo pip3 install psycopg2-binary
print_delimiter

if ! [ -x "$(command -v jython)" ]; then
    print_title "[~] Install Jython"
    sudo apt-get install -y jython
else
    print_title "[+] Jython is already installed"
fi
print_delimiter


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
print_delimiter

if ! [ -x "$(command -v perl)" ]; then
    print_title "[~] Install Perl and useful related packages"
    sudo apt-get install -y --ignore-missing perl libwhisker2-perl libwww-perl
else
    print_title "[+] Perl is already installed"
fi
print_delimiter

if ! [ -x "$(command -v php)" ]; then
    print_title "[~] Install PHP"
    sudo apt-get install -y --ignore-missing php
else
    print_title "[+] PHP is already installed"
fi
print_delimiter

if ! [ -x "$(command -v java)" ]; then
    print_title "[~] Install Java"
    sudo apt-get install -y --ignore-missing default-jdk
else
    print_title "[+] Java is already installed"
fi
print_delimiter

print_title "[~] Install other required packages (if missing)"
sudo apt-get install -y --ignore-missing zlib1g-dev libcurl4-openssl-dev liblzma-dev 
sudo apt-get install -y --ignore-missing libxml2 libxml2-dev libxslt1-dev build-essential 
sudo apt-get install -y --ignore-missing gcc make automake patch libssl-dev locate
sudo apt-get install -y --ignore-missing smbclient dnsutils libgmp-dev libffi-dev 
sudo apt-get install -y --ignore-missing libxml2-utils unixodbc unixodbc-dev alien
print_delimiter

print_title "[~] Install Python3 libraries required by Jok3r (if missing)"
sudo pip3 install -r requirements.txt

print_title "[~] Disable UserWarning related to psycopg2"
sudo pip3 uninstall psycopg2-binary -y
sudo pip3 uninstall psycopg2 -y
sudo pip3 install psycopg2-binary

print_title "[~] Dependencies installation finished. Check if any error has been raised"
