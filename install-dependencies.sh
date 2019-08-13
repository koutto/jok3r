#!/usr/bin/env bash 

print_green() {
    BOLD_GREEN=$(tput bold ; tput setaf 2)
    NORMAL=$(tput sgr0)
    echo "${BOLD_GREEN}$1${NORMAL}"
}

print_yellow() {
    BOLD_YELLOW=$(tput bold ; tput setaf 3)
    NORMAL=$(tput sgr0)
    echo "${BOLD_YELLOW}$1${NORMAL}"
}

print_red() {
    BOLD_YELLOW=$(tput bold ; tput setaf 1)
    NORMAL=$(tput sgr0)
    echo "${BOLD_YELLOW}$1${NORMAL}"
}

print_blue() {
    BOLD_YELLOW=$(tput bold ; tput setaf 4)
    NORMAL=$(tput sgr0)
    echo "${BOLD_YELLOW}$1${NORMAL}"
}

print_delimiter() {
    echo
    echo "-------------------------------------------------------------------------------"
    echo
}

echo
echo
print_blue "=============================="
print_blue " Jok3r - Dependencies Install "
print_blue "=============================="
echo
echo
print_blue "This script will install Jok3r and all the required dependencies"

# Make sure we are root !
if [ "$EUID" -ne 0 ]; then 
    print_red "[!] Must be run as root"
    exit 1
fi

# Make sure we are on Debian-based OS
OS=`(lsb_release -sd || grep DISTRIB_ID /etc/*-release) 2> /dev/null`
print_blue "[~] Detected OS:"
echo $OS
if [[ `echo $OS | egrep -i '(kali|debian|ubuntu)'` ]]; then
    print_green "[+] Debian-based Linux OS detected !"
else
    print_red "[!] No Debian-based Linux OS detected (Debian/Ubuntu/Kali). Will not be able to continue !"
    exit 1
fi
echo
echo

# -----------------------------------------------------------------------------
# Add Kali repositories if not on Kali (Debian/Ubuntu)

if [[ ! $(grep "deb http://http.kali.org/kali kali-rolling main" /etc/apt/sources.list) ]]; then 
    print_blue "[~] Add Kali repository (because missing in /etc/apt/sources.list)"
    cp /etc/apt/sources.list /etc/apt/sources.list.bak
    echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
    cd /tmp/
    wget -k https://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2018.1_all.deb
    dpkg -i kali-archive-keyring_2018.1_all.deb
    rm -f kali-archive-keyring_2018.1_all.deb
    apt-get update
    apt-get install -y kali-archive-keyring
    if [ $? -eq 0 ]; then
        print_green "[+] Kali repository added with success"
    else
        print_red "[!] Error occured while adding Kali repository"
        exit 1
    fi
else
    print_blue "[~] Kali repository detected in /etc/apt/sources.list. Updating repositories..."
    apt-get update
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Git

if ! [ -x "$(command -v git)" ]; then
    print_blue "[~] Install git ..."
    apt-get install -y git
    if [ -x "$(command -v git)" ]; then
        print_green "[+] Git installed successfully"
    else
        print_red "[!] An error occured during Git install"
        exit 1
    fi
else
    print_green "[+] Git is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Metasploit-framework

if ! [ -x "$(command -v msfconsole)" ]; then
    print_blue "[~] Install Metasploit ..."
    apt-get install -y metasploit-framework 
    if [ -x "$(command -v msfconsole)" ]; then
        print_green "[+] Metasploit installed successfully"
    else
        print_red "[!] An error occured during Metasploit install"
        exit 1
    fi        
else
    print_green "[+] Metasploit is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Nmap 

if ! [ -x "$(command -v nmap)" ]; then
    print_blue "[~] Install Nmap ..."
    apt-get install -y nmap 
    if [ -x "$(command -v nmap)" ]; then
        print_green "[+] Nmap installed successfully"
    else
        print_red "[!] An error occured during Nmap install"
        exit 1
    fi   
else
    print_green "[+] Nmap is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Tcpdump

if ! [ -x "$(command -v tcpdump)" ]; then
    print_blue "[~] Install tcpdump ..."
    apt-get install -y tcpdump
    if [ -x "$(command -v tcpdump)" ]; then
        print_green "[+] tcpdump installed successfully"
    else
        print_red "[!] An error occured during tcpdump install"
        exit 1
    fi   
else
    print_green "[+] tcpdump is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

# if ! [ -x "$(command -v npm)" ]; then
#     print_green "[~] Install NodeJS ..."
#     curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
#     apt-get install -y nodejs
# else
#     print_green "[+] NodeJS is already installed"
# fi
# print_delimiter   

# -----------------------------------------------------------------------------
# Install Python and related packages

print_blue "[~] Install Python 2.7 + 3 and useful related packages (if missing)"
if [[ ! $(dpkg-query -W -f='${Status}' python 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python2.7 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python2.7 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python3 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python3 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python-pip 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python-pip 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python3-pip 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python3-pip 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python-dev 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python3-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python3-dev 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python-setuptools 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python-setuptools
fi
if [[ ! $(dpkg-query -W -f='${Status}' python3-setuptools 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python3-setuptools 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python3-distutils 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python3-distutils 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python-ipy 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python-ipy 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python-nmap 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python-nmap 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python3-pymysql 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python3-pymysql 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python3-psycopg2 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python3-psycopg2 
fi
if [[ ! $(dpkg-query -W -f='${Status}' python3-shodan 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y python3-shodan 
fi
pip2 install --upgrade pip
pip3 install --upgrade pip
# pip3 uninstall -y psycopg2
# pip3 install psycopg2-binary
if [ -x "$(command -v python2.7)" ]; then
    print_green "[+] Python2.7 installed successfully"
else
    print_red "[!] An error occured during Python2.7 install"
    exit 1
fi 
if [ -x "$(command -v python3)" ]; then
    print_green "[+] Python3 installed successfully"
else
    print_red "[!] An error occured during Python2.7 install"
    exit 1
fi 
if [ -x "$(command -v pip2)" ]; then
    print_green "[+] pip2 installed successfully"
else
    print_red "[!] An error occured during pip2 install"
    exit 1
fi 
if [ -x "$(command -v pip3)" ]; then
    print_green "[+] pip3 installed successfully"
else
    print_red "[!] An error occured during pip3 install"
    exit 1
fi 
print_delimiter

# -----------------------------------------------------------------------------
# Install Python virtualenv

if ! [ -x "$(command -v virtualenv)" ]; then
    print_blue "[~] Install python virtual environment packages"
    pip2 install virtualenv
    pip3 install virtualenv
    # pip3 install virtualenvwrapper
    # source /usr/local/bin/virtualenvwrapper.sh
    if [ -x "$(command -v virtualenv)" ]; then
        print_green "[+] virtualenv installed successfully"
    else
        print_red "[!] An error occured during virtualenv install"
        exit 1
    fi
else
    print_green "[+] Python virtualenv is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install common Python libraries
# We decide to add system-wide install of common Python libraries even if
# most of Python tools are then installed inside virtualenv, because it appears
# that a lot of projects/tools do not embed correct requirements.txt or
# setup.py. Then virtualenv for Python projects are created with 
# --system-site-package option which allows to access those libraries.

print_blue "[~] Install common Python libraries..."

LIBPY2="
argcomplete
asn1crypto
bcrypt
beautifulsoup4
bs4
cement
certifi
cffi
chardet
colorama
colorlog
configparser
cryptography
cssselect
dnspython
entrypoints
enum34
Flask
future
futures
gpg
html-similarity
html5lib
humanize
ipaddress
IPy
keyring
keyrings.alt
ldap3
ldapdomaindump
lxml
macholib
MarkupSafe
maxminddb
paramiko
parsel
passlib
pluginbase
proxy-db
py2-ipaddress
pyasn1
pycparser
pycrypto
pycryptodomex
pycurl
PyGObject
pymssql
PyNaCl
pyOpenSSL
pystache
python-nmap
pyxdg
requests
requests-mock
scapy
SecretStorage
six
termcolor
urllib3
virtualenv
w3lib
webencodings
Werkzeug
"

PIP2FREEZE=$(pip2 freeze)
for lib in $LIBPY2; do    
    if [[ ! $(echo $PIP2FREEZE | grep -i $lib) ]]; then
        print_blue "[~] Install Python library ${lib} (py2)"
        pip2 install $lib
    fi
done

LIBPY3="
aiohttp
ansi2html
asn1crypto
async-timeout
asyncio
attrs
Babel
bcrypt
beautifulsoup4
blessed
bs4
Cerberus
certifi
cffi
chardet
cmd2
colorama
colored
colorlog
cryptography
dnspython
docutils
enlighten
entrypoints
Flask
future
html5lib
humanfriendly
idna
imagesize
inflect
ipparser
itsdangerous
keyring
keyrings.alt
ldap3
ldapdomaindump
logutils
lxml
MarkupSafe
multidict
netaddr
ntlm-auth
packaging
paramiko
pbr
Pillow
pluginbase
ply
pockets
prettytable
prompt-toolkit
psycopg2
psycopg2-binary
pyasn1
pycparser
pycrypto
pycryptodomex
pycurl
Pygments
PyGObject
pymongo
PyMySQL
PyNaCl
pyodbc
pyOpenSSL
pyparsing
pyperclip
pysmi
pysnmp
PySocks
python-libnmap
python-memcached
pytz
pyxdg
PyYAML
redis
regex
requests
requests-ntlm
requests-toolbelt
SecretStorage
selenium
shodan
six
snowballstemmer
soupsieve=
Sphinx
sphinx-better-theme
sphinxcontrib-napoleon
sphinxcontrib-websupport
SQLAlchemy
SQLAlchemy-Utils
stem
stevedore
tabulate
termcolor
tld
tqdm
urllib3
veryprettytable
virtualenv
virtualenv-clone
virtualenvwrapper
wcwidth
webencodings
Werkzeug
yarl
"

PIP3FREEZE=$(pip3 freeze)
for lib in $LIBPY3; do    
    if [[ ! $(echo $PIP3FREEZE | grep -i $lib) ]]; then
        print_blue "[~] Install Python library ${lib} (py3)"
        pip3 install $lib
    fi
done

print_delimiter

# -----------------------------------------------------------------------------
# Install Jython

if ! [ -x "$(command -v jython)" ]; then
    print_blue "[~] Install Jython"
    apt-get install -y jython
    if [ -x "$(command -v jython)" ]; then
        print_green "[+] Jython installed successfully"
    else
        print_red "[!] An error occured during Jython install"
        exit 1
    fi   
else
    print_green "[+] Jython is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Ruby

if ! [ -x "$(command -v ruby)" ]; then
    print_blue "[~] Install Ruby"
    apt-get install -y ruby ruby-dev
    if [ -x "$(command -v ruby)" ]; then
        print_green "[+] Ruby installed successfully"
    else
        print_red "[!] An error occured during Ruby install"
        exit 1
    fi   
else
    print_green "[+] Ruby is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install RVM (Ruby Version Manager)

if ! [ -x "$(command -v rvm)" ]; then
    print_blue "[~] Install Ruby RVM (Ruby Version Manager)"
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
    if [ -x "$(command -v rvm)" ]; then
        print_green "[+] Ruby RVM installed successfully"
    else
        print_red "[!] An error occured during Ruby RVM install"
        exit 1
    fi   
else
    print_green "[+] Ruby RVM is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install different versions of Ruby via RVM

if [[ ! $(rvm list | grep ruby-2.4) ]]; then
    print_blue "[~] Install Ruby 2.4 (old version)"
    apt-get install -y ruby-psych
    apt-get purge -y libssl-dev
    apt-get install -y libssl1.0-dev
    rvm install ruby-2.4
    if [[ ! $(rvm list | grep ruby-2.4) ]]; then
        print_red "[!] Ruby 2.4 has not been installed correctly with RVM"
        exit 1
    else
        rvm list
        print_green "[+] Ruby 2.4 has been successfully installed with RVM"
    fi
else
    print_green "[+] Ruby 2.4 is already installed"
fi
print_delimiter

# if ! rvm list | grep -q "ruby-2.5"
# then
#     print_green "[~] Install Ruby 2.5 (default)"
#     rvm install ruby-2.5
#     rvm --default use 2.5
#     gem install ffi
#     rvm list
# fi

if [[ ! $(rvm list | grep ruby-2.6) ]]; then
    print_blue "[~] Install Ruby 2.6"
    rvm install ruby-2.6
    rvm --default use ruby-2.6
    gem install ffi
    if [[ ! $(rvm list | grep ruby-2.6) ]]; then
        print_red "[!] Ruby 2.6 has not been installed correctly with RVM"
        exit 1
    else
        rvm list
        print_green "[+] Ruby 2.6 has been successfully installed with RVM"
    fi
else
    print_green "[+] Ruby 2.6 is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------

print_blue "[~] Update Ruby bundler"
gem install bundler
print_delimiter

# -----------------------------------------------------------------------------
# Install Perl

if ! [ -x "$(command -v perl)" ]; then
    print_blue "[~] Install Perl"
    apt-get install -y perl 
    if [ -x "$(command -v perl)" ]; then
        print_green "[+] Perl installed successfully"
    else
        print_red "[!] An error occured during Perl install"
        exit 1
    fi   
else
    print_green "[+] Perl is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install PHP

if ! [ -x "$(command -v php)" ]; then
    print_blue "[~] Install PHP"
    apt-get install -y php
    if [ -x "$(command -v php)" ]; then
        print_green "[+] PHP installed successfully"
    else
        print_red "[!] An error occured during PHP install"
        exit 1
    fi   
else
    print_green "[+] PHP is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Java

if ! [ -x "$(command -v java)" ]; then
    print_blue "[~] Install Java"
    apt-get install -y default-jdk
    if [ -x "$(command -v jython)" ]; then
        print_green "[+] Java installed successfully"
    else
        print_red "[!] An error occured during Java install"
        exit 1
    fi   
else
    print_green "[+] Java is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Firefox

if ! [ -x "$(command -v firefox)" ]; then
    print_blue "[~] Install Firefox (for HTML reports and web screenshots)"
    apt-get install -y firefox-esr
    if [ -x "$(command -v firefox)" ]; then
        print_green "[+] Firefox installed successfully"
    else
        print_red "[!] An error occured during Firefox install"
        exit 1
    fi   
else
    print_green "[+] Firefox is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Geckodriver

if ! [ -x "$(command -v geckodriver)" ]; then
    print_blue "[~] Install Geckodriver (for web screenshots)"
    cd /tmp/
    MACHINE_TYPE=`uname -m`
    if [ ${MACHINE_TYPE} == 'x86_64' ]; then
        wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz
        tar -xvf geckodriver-v0.24.0-linux64.tar.gz
        rm -f geckodriver-v0.24.0-linux64.tar.gz
        mv geckodriver /usr/sbin
        if [ -e /usr/bin/geckodriver ]; then
            rm /usr/bin/geckodriver
        fi
        ln -s /usr/sbin/geckodriver /usr/bin/geckodriver
    else
        wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux32.tar.gz
        tar -xvf geckodriver-v0.24.0-linux32.tar.gz
        rm -f geckodriver-v0.24.0-linux32.tar.gz
        mv geckodriver /usr/sbin
        if [ -e /usr/bin/geckodriver ]; then
            rm /usr/bin/geckodriver
        fi
        ln -s /usr/sbin/geckodriver /usr/bin/geckodriver
    fi
    if [ -x "$(command -v geckodriver)" ]; then
        print_green "[+] Geckodriver installed successfully"
    else
        print_red "[!] An error occured during Geckodriver install"
        exit 1
    fi   
else
    print_green "[+] Geckodriver is already installed"
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install various required packages 

print_blue "[~] Install other required packages (if missing)"
if [[ ! $(dpkg-query -W -f='${Status}' zlib1g-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y zlib1g-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' libcurl4-openssl-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libcurl4-openssl-dev 
fi
if [[ ! $(dpkg-query -W -f='${Status}' liblzma-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y liblzma-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' libxml2 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libxml2
fi
if [[ ! $(dpkg-query -W -f='${Status}' libxml2-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libxml2-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' libxslt1-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libxslt1-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' build-essential 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y build-essential 
fi
if [[ ! $(dpkg-query -W -f='${Status}' gcc 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y gcc 
fi
if [[ ! $(dpkg-query -W -f='${Status}' make 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y make
fi
if [[ ! $(dpkg-query -W -f='${Status}' automake 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y automake
fi
if [[ ! $(dpkg-query -W -f='${Status}' patch 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y patch
fi
if [[ ! $(dpkg-query -W -f='${Status}' libssl-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libssl-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' locate 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y locate
fi
if [[ ! $(dpkg-query -W -f='${Status}' smbclient 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y smbclient
fi
if [[ ! $(dpkg-query -W -f='${Status}' dnsutils 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y dnsutils 
fi
if [[ ! $(dpkg-query -W -f='${Status}' libgmp-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libgmp-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' libffi-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libffi-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' libxml2-utils 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libxml2-utils
fi
if [[ ! $(dpkg-query -W -f='${Status}' unixodbc 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y unixodbc
fi
if [[ ! $(dpkg-query -W -f='${Status}' unixodbc-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y unixodbc-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' alien 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y alien
fi
if [[ ! $(dpkg-query -W -f='${Status}' bc 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y bc
fi
if [[ ! $(dpkg-query -W -f='${Status}' libwhisker2-perl 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libwhisker2-perl
fi
if [[ ! $(dpkg-query -W -f='${Status}' libwww-perl 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libwww-perl
fi
if [[ ! $(dpkg-query -W -f='${Status}' postgresql 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y postgresql
fi
if [[ ! $(dpkg-query -W -f='${Status}' postgresql-contrib 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y postgresql-contrib
fi
if [[ ! $(dpkg-query -W -f='${Status}' libpq-dev 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y libpq-dev
fi
if [[ ! $(dpkg-query -W -f='${Status}' net-tools 2>/dev/null | grep "ok installed") ]]; then
    apt-get install -y net-tools
fi
print_delimiter

# -----------------------------------------------------------------------------

print_blue "[~] Install Python3 libraries required by Jok3r (if missing)"
pip3 install -r requirements.txt
pip3 install --upgrade requests
print_delimiter

# -----------------------------------------------------------------------------

print_blue "[~] Disable UserWarning related to psycopg2"
pip3 uninstall psycopg2-binary -y
pip3 uninstall psycopg2 -y
pip3 install psycopg2-binary
print_delimiter

# -----------------------------------------------------------------------------

print_blue "[~] Cleaning apt cache..."
apt-get clean
rm -rf /var/lib/apt/lists/*
print_delimiter

# -----------------------------------------------------------------------------

print_green "[~] Dependencies installation finished."
print_green "[~] IMPORTANT: Make sure to check if any error has been raised"
echo
