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
    BOLD_RED=$(tput bold ; tput setaf 1)
    NORMAL=$(tput sgr0)
    echo "${BOLD_RED}$1${NORMAL}"
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

# -----------------------------------------------------------------------------
# Install Git

if ! [ -x "$(command -v git)" ]; then
    print_blue "[~] Install git ..."
    pacman -S git
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
# Install various required packages 

print_blue "[~] Install various required packages (if missing)"

PACKAGES="
automake
bc
curl
dnsutils
gawk
gcc
gnupg2
iputils-ping
libcurl-openssl
libffi
libgmp-static
python2-pyliblzma 
libpqxx
python2-pyopenssl
libwhisker2-perl
libwww-perl
libxml2
python2-libxml
libxslt
locales
locate
make
net-tools
patch
postgresql
procps
smbclient
sudo
unixodbc
unixodbc-dev
unzip
wget
zlib
"
for package in $PACKAGES; do    
    if ! pacman -Q -f='${Status}' $PACKAGE 2>/dev/null | grep "ok installed"; then
        echo
        print_blue "[~] Install ${PACKAGE} ..."
        pacman -S $PACKAGE
    fi
done
print_delimiter

# -----------------------------------------------------------------------------
# Install Metasploit-framework

if ! [ -x "$(command -v msfconsole)" ]; then
    print_blue "[~] Install Metasploit ..."
    pacman -S metasploit-framework 
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
    pacman -S nmap 
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
    pacman -S tcpdump
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
# Install Python and related packages
print_blue "[~] Install Python 2.7 + 3 and useful related packages (if missing)"

PACKAGES="
python
python27
python-pip
python-setuptools
python-ipy
python-nmap
python-pymysql
python-psycopg2
python-shodan
"

for package in $PACKAGES; do    
    if ! pacman -Q -f='${Status}' $PACKAGE 2>/dev/null | grep "ok installed"; then
        echo
        print_blue "[~] Install ${PACKAGE} ..."
        pacman -S $PACKAGE 
    fi
done

python2.7 -m pip install --upgrade pip
pip install --upgrade pip
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
if [ -x "$(command -v python2.7 -m pip)" ]; then
    print_green "[+] pip2 installed successfully"
else
    print_red "[!] An error occured during pip2 install"
    exit 1
fi 
if [ -x "$(command -v pip)" ]; then
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
    python2.7 -m pip install virtualenv --user
    pip install virtualenv --user
    pip install virtualenvwrapper --user
    source /usr/bin/virtualenvwrapper.sh
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

PIP2FREEZE=$(python2.7 -m pip freeze)
for lib in $LIBPY2; do    
    if ! echo $PIP2FREEZE | grep -i $lib; then
        echo
        print_blue "[~] Install Python library ${lib} (py2)"
        python2.7 -m pip install $lib --user
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
cement
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
soupsieve
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

PIP3FREEZE=$(pip freeze)
for lib in $LIBPY3; do    
    if ! echo $PIP3FREEZE | grep -i $lib; then
        echo
        print_blue "[~] Install Python library ${lib} (py3)"
        pip install $lib --user
    fi
done

print_delimiter

# -----------------------------------------------------------------------------
# Install Jython

if ! [ -x "$(command -v jython)" ]; then
    print_blue "[~] Install Jython"
    pacman -S jython
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
    pacman -S ruby
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
# Install different versions of Ruby via RVM

if [ -a /home/mrgfy/.rvm/src/rvm/scripts/rvm ]; then
    source /home/mrgfy/.rvm/src/rvm/scripts/rvm
fi
if ! rvm list | grep ruby-2.4; then
    print_blue "[~] Install Ruby 2.4 (old version)"
    pacman -S ruby-psych
    rvm install ruby-2.4
    if ! rvm list | grep ruby-2.4; then
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

if ! rvm list | grep -q "ruby-2.5"; then
    print_green "[~] Install Ruby 2.5 (default)"
    rvm install ruby-2.5
    rvm --default use 2.5
    gem install ffi
    rvm list
fi

if ! rvm list | grep ruby-2.6; then
    print_blue "[~] Install Ruby 2.6"
    rvm install ruby-2.6
    rvm --default use ruby-2.6
    gem install ffi
    if ! rvm list | grep ruby-2.6; then
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
    pacman -S perl 
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
    pacman -S php
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
    pacman -S default-jdk
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
    pacman -S firefox-esr
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
