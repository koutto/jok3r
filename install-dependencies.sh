#!/usr/bin/env bash

print_title() {
    BOLD_GREEN=$(tput bold ; tput setaf 2)
    NORMAL=$(tput sgr0)
    echo "${BOLD_GREEN} $1 ${NORMAL}"
}

print_yellow() {
    BOLD_YELLOW=$(tput bold ; tput setaf 3)
    NORMAL=$(tput sgr0)
    echo "${BOLD_YELLOW} $1 ${NORMAL}"
}

print_delimiter() {
    echo
    echo "-------------------------------------------------------------------------------"
    echo
}

clear

echo
echo
print_title "=============================="
print_title "Install dependencies for Jok3r"
print_title "=============================="
echo
echo

# Make sure we are root !
if [ "$EUID" -ne 0 ]; then 
    print_yellow "Please run as root"
    exit
fi

# Make sure we are on Kali
if [[ `(lsb_release -sd || grep ^PRETTY_NAME /etc/os-release) 2>/dev/null | grep "Kali GNU/Linux.*\(2\|Rolling\)"` ]]; then
    echo "Kali Linux detected !"
else
    print_yellow "Kali Linux not detected ! There is no guarantee Jok3r will be working correctly."
    print_yellow "It is strongly advised to use Docker environment instead !"
fi
echo
echo

# -----------------------------------------------------------------------------

print_title "[~] Update repositories"
apt-get update
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v git)" ]; then
    print_title "[~] Install git ..."
    apt-get install -y git
else
    print_title "[+] Git is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v msfconsole)" ]; then
    print_title "[~] Install Metasploit ..."
    apt-get install -y metasploit-framework 
else
    print_title "[+] Metasploit is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v nmap)" ]; then
    print_title "[~] Install Nmap ..."
    apt-get install -y nmap 
else
    print_title "[+] Nmap is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v tcpdump)" ]; then
    print_title "[~] Install tcpdump ..."
    apt-get install -y tcpdump
else
    print_title "[+] tcpdump is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v npm)" ]; then
    print_title "[~] Install NodeJS ..."
    curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
    apt-get install -y nodejs
else
    print_title "[+] NodeJS is already installed"
fi
print_delimiter   

# -----------------------------------------------------------------------------

print_title "[~] Install Python 2.7 + 3 and useful related packages (if missing)"
apt-get install -y --ignore-missing python 
apt-get install -y --ignore-missing python2.7 
apt-get install -y --ignore-missing python3 
apt-get install -y --ignore-missing python-pip 
apt-get install -y --ignore-missing python3-pip 
apt-get install -y --ignore-missing python-dev 
apt-get install -y --ignore-missing python3-dev 
apt-get install -y --ignore-missing python-setuptools 
apt-get install -y --ignore-missing python3-setuptools 
apt-get install -y --ignore-missing python3-distutils
apt-get install -y --ignore-missing python-ipy 
apt-get install -y --ignore-missing python-nmap 
apt-get install -y --ignore-missing python3-pymysql
apt-get install -y --ignore-missing python3-psycopg2
apt-get install -y --ignore-missing python3-shodan
pip2 install --upgrade pip
pip3 install --upgrade pip
pip3 uninstall -y psycopg2
pip3 install psycopg2-binary
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v jython)" ]; then
    print_title "[~] Install Jython"
    apt-get install -y jython
else
    print_title "[+] Jython is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v rvm)" ]; then
    print_title "[~] Install Ruby latest + old version (2.3) required for some tools"
    #sudo apt-get install -y --ignore-missing ruby ruby-dev
    curl -sSL https://get.rvm.io | bash
    source /etc/profile.d/rvm.sh
    if ! grep -q "source /etc/profile.d/rvm.sh" ~/.bashrc
    then
        echo "source /etc/profile.d/rvm.sh" >> ~/.bashrc
    fi
    # Make sure rvm will be available
    if ! grep -q "[[ -s /usr/local/rvm/scripts/rvm ]] && source /usr/local/rvm/scripts/rvm" ~/.bashrc
    then
        echo "[[ -s /usr/local/rvm/scripts/rvm ]] && source /usr/local/rvm/scripts/rvm" >> ~/.bashrc
    fi
    source ~/.bashrc
fi

if ! rvm list | grep -q "ruby-2.4"
then
    print_title "[~] Install Ruby old version (2.4) required for some tools"
    apt-get install -y ruby-psych
    apt-get purge -y libssl-dev
    apt-get install -y libssl1.0-dev
    rvm install 2.4
fi

if ! rvm list | grep -q "ruby-2.5"
then
    print_title "[~] Install Ruby 2.5 (default)"
    rvm install ruby-2.5
    rvm --default use 2.5
    gem install ffi
    rvm list
fi

print_delimiter

print_title "[~] Update Ruby bundler"
gem install bundler
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v perl)" ]; then
    print_title "[~] Install Perl and useful related packages"
    apt-get install -y --ignore-missing perl 
else
    print_title "[+] Perl is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v php)" ]; then
    print_title "[~] Install PHP"
    apt-get install -y --ignore-missing php
else
    print_title "[+] PHP is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v java)" ]; then
    print_title "[~] Install Java"
    apt-get install -y --ignore-missing default-jdk
else
    print_title "[+] Java is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

if ! [ -x "$(command -v firefox)" ]; then
    print_title "[~] Install Firefox (for HTML reports and web screenshots)"
    apt-get install -y --ignore-missing firefox-esr
else
    print_title "[+] Firefox is already installed"
fi
print_delimiter

if ! [ -x "$(command -v geckodriver)" ]; then
    print_title "[~] Install Geckodriver (for web screenshots)"
    mv /tmp/
    MACHINE_TYPE=`uname -m`
    if [ ${MACHINE_TYPE} == 'x86_64' ]; then
        wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz
        tar -xvf geckodriver-v0.24.0-linux64.tar.gz
        rm geckodriver-v0.24.0-linux64.tar.gz
        mv geckodriver /usr/sbin
        if [ -e /usr/bin/geckodriver ]; then
            rm /usr/bin/geckodriver
        fi
        ln -s /usr/sbin/geckodriver /usr/bin/geckodriver
    else
        wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux32.tar.gz
        tar -xvf geckodriver-v0.24.0-linux32.tar.gz
        rm geckodriver-v0.24.0-linux32.tar.gz
        mv geckodriver /usr/sbin
        if [ -e /usr/bin/geckodriver ]; then
            rm /usr/bin/geckodriver
        fi
        ln -s /usr/sbin/geckodriver /usr/bin/geckodriver
    fi
else
    print_title "[+] Geckodriver is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

print_title "[~] Install other required packages (if missing)"
apt-get install -y --ignore-missing zlib1g-dev 
apt-get install -y --ignore-missing libcurl4-openssl-dev 
apt-get install -y --ignore-missing liblzma-dev 
apt-get install -y --ignore-missing libxml2 
apt-get install -y --ignore-missing libxml2-dev 
apt-get install -y --ignore-missing libxslt1-dev 
apt-get install -y --ignore-missing build-essential 
apt-get install -y --ignore-missing gcc 
apt-get install -y --ignore-missing make 
apt-get install -y --ignore-missing automake 
apt-get install -y --ignore-missing patch 
apt-get install -y --ignore-missing libssl-dev 
apt-get install -y --ignore-missing locate
apt-get install -y --ignore-missing smbclient 
apt-get install -y --ignore-missing dnsutils 
apt-get install -y --ignore-missing libgmp-dev 
apt-get install -y --ignore-missing libffi-dev 
apt-get install -y --ignore-missing libxml2-utils 
apt-get install -y --ignore-missing unixodbc 
apt-get install -y --ignore-missing unixodbc-dev 
apt-get install -y --ignore-missing alien
apt-get install -y --ignore-missing bc 
apt-get install -y --ignore-missing libwhisker2-perl 
apt-get install -y --ignore-missing libwww-perl 
apt-get install -y --ignore-missing postgresql
apt-get install -y --ignore-missing postgresql-contrib 
apt-get install -y --ignore-missing libpq-dev 
apt-get install -y --ignore-missing net-tools
print_delimiter

# -----------------------------------------------------------------------------

print_title "[~] Install Python3 libraries required by Jok3r (if missing)"
pip3 install -r requirements.txt
pip3 install --upgrade requests
print_delimiter

# -----------------------------------------------------------------------------

print_title "[~] Install virtual environment packages"
pip2 install virtualenv
pip3 install virtualenv
# pip3 install virtualenvwrapper
# source /usr/local/bin/virtualenvwrapper.sh
print_delimiter

# -----------------------------------------------------------------------------

print_title "[~] Disable UserWarning related to psycopg2"
pip3 uninstall psycopg2-binary -y
pip3 uninstall psycopg2 -y
pip3 install psycopg2-binary
print_delimiter

# -----------------------------------------------------------------------------
apt-get clean

print_title "[~] Dependencies installation finished."
print_title "[~] IMPORTANT: Make sure to check if any error has been raised"
echo
