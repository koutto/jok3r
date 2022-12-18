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
    BOLD_BLUE=$(tput bold ; tput setaf 4)
    NORMAL=$(tput sgr0)
    echo "${BOLD_BLUE}$1${NORMAL}"
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
#OS="$(lsb_release -sd || grep NAME /etc/*-release) 2> /dev/null)"
#print_blue "[~] Detected OS:"
#echo "$OS"
#if [[ "$(echo $OS | grep -q '(arch|arco|blackarch|archstrike|manjaro)')" ]]; then
#    print_green "[+] Arch-based Linux OS detected !"
#else
#    print_red "[!] No Arch-based Linux OS detected Arch, Arco, Blackarch, Archstrike or Manjaro. Will not be able to continue."
#    exit 1
#fi
echo
echo

# -----------------------------------------------------------------------------
# Add BlackArch repository

if ! [[ -x "$(grep -q "blackarch" /etc/pacman.conf)" ]]; then
    print_blue "[~] Add BlackArch repository (because missing in /etc/pacman.conf)"
    # Run https://blackarch.org/strap.sh as root and follow the instructions.
    curl -O https://blackarch.org/strap.sh
    # Verify the SHA1 sum
    echo 5ea40d49ecd14c2e024deecf90605426db97ea0c strap.sh | sha1sum -c
    # Set execute bit
    chmod +x strap.sh
    # Run strap.sh
    ./strap.sh
    # Enable multilib following https://wiki.archlinux.org/index.php/Official_repositories#Enabling_multilib and run:
    pacman -Syu
    if ! [[ -x "$(grep -q "blackarch" /etc/pacman.conf)" ]]; then
        print_green "[+] BlackArch repository added with success"
    else
        print_red "[!] Error occured while adding BlackArch repository"
        exit 1
    fi
else
    print_blue "[~] BlackArch repository detected in /etc/pacman-conf. Updating repositories..."
    pacman -Syu
    if grep -q "blackarch" /etc/pacman.conf = 0; then
        print_green "[+] Repositories updated with success"
    else
        print_red "[!] Error occured while updating repositories"
        exit 1
    fi
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Git

if ! [ -x "$(command -v git)" ]; then
    print_blue "[~] Install git ..."
    pacman -S --needed --noconfirm git
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

PACKAGES="curl dnsutils gawk gcc gnupg iputils openssl libffi lrzip xz perl-libwhisker2 perl-libwww libxml2
 libxslt mlocate make inetutils patch postgresql postgresql-libs procps samba unixodbc unzip wget zlib python python-pip"

for package in $PACKAGES; do
    if ! [[ -x "$(pacman -Ss "$package" | grep "installed")" ]]; then
        echo
        touch /var/log/journal/%m 2>/dev/null
        print_blue "[~] Install ${package} ..."
        pacman -S --needed --noconfirm "$package"
    fi
done
print_delimiter

# -----------------------------------------------------------------------------
# Install python3.6

print_blue "[~] Install Python3.6"

if ! [ -x "$(command -v python3.6)" ]; then
    echo
    wget https://aur.archlinux.org/cgit/aur.git/snapshot/python36.tar.gz
    tar -xzvvf python36.tar.gz
    cd python36 || exit 1
    runuser "$USER" -c makepkg -si --noconfirm --needed
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Metasploit-framework

if ! [ -x "$(command -v msfconsole)" ]; then
    print_blue "[~] Install Metasploit ..."
    pacman -S --needed --noconfirm metasploit
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
    pacman -S --needed --noconfirm nmap
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
    pacman -S --needed --noconfirm tcpdump
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
#     pacman -S --needed --noconfirm nodejs
# else
#     print_green "[+] NodeJS is already installed"
# fi
# print_delimiter

# -----------------------------------------------------------------------------
# Install Python and related packages
print_blue "[~] Install Python 2.7 + 3 and useful related packages (if missing)"

PACKAGES="python2 python2-pip python-setuptools python-distutils-extra python-ipy python2-python-nmap python-pymysql python-psycopg2 python-shodan"

for package in $PACKAGES; do
    if ! [[ -x "$(pacman -Ss "$package" | grep "installed")" ]]; then
        echo
        print_blue "[~] Install ${package} ..."
        pacman -S --needed --noconfirm "$package"
    fi
done

python3.6 -m ensurepip
pip2 install --upgrade pip
pip3 install --upgrade pip
# python3.6 -m pip uninstall -y psycopg2
# python3.6 -m pip install psycopg2-binary
if [ -x "$(command -v python2.7)" ]; then
    print_green "[+] Python2.7 installed successfully"
else
    print_red "[!] An error occured during Python2.7 install"
    exit 1
fi
if [ -x "$(command -v python3.6)" ]; then
    print_green "[+] python3.6 installed successfully"
else
    print_red "[!] An error occured during Python3.6 install"
    exit 1
fi
if [ -x "$(command -v python3.6 -m pip)" ]; then
    print_green "[+] python3.6 -m pip installed successfully"
else
    print_red "[!] An error occured during python3.6 -m pip install"
    exit 1
fi
print_delimiter

# -----------------------------------------------------------------------------
# Install Python virtualenv

if ! [ -x "$(command -v virtualenv)" ]; then
    print_blue "[~] Install python virtual environment packages"
    python2.7 -m pip install virtualenv
    python3.6 -m pip install virtualenv
    # python3.6 -m pip install virtualenvwrapper
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

LIBPY2="argcomplete asn1crypto bcrypt beautifulsoup4 bs4 certifi cffi chardet colorama colorlog configparser cryptography cssselect dnspython entrypoints enum34 Flask future futures gpg html-similarity html5lib humanize ipaddress IPy keyring keyrings.alt ldap3 ldapdomaindump lxml macholib MarkupSafe maxminddb paramiko parsel passlib pluginbase proxy-db py2-ipaddress pyasn1 pycparser pycrypto pycryptodomex pycurl PyGObject pymssql PyNaCl pyOpenSSL pystache python-nmap pyxdg requests requests-mock scapy SecretStorage six termcolor urllib3 virtualenv w3lib webencodings Werkzeug"

python2.7 -m pip FREEZE="$(python2.7 -m pip freeze)"
for lib in $LIBPY2; do
    if [[ ! "$(python2.7 -m pip FREEZE | grep -i "$lib")" = 0 ]]; then
        echo
        print_blue "[~] Install Python library ${lib} (py2)"
        python2.7 -m pip install "$lib"
    fi
done

LIBPY3="aiohttp ansi2html asn1crypto async-timeout asyncio attrs Babel bcrypt beautifulsoup4 blessed bs4 cement Cerberus certifi cffi chardet cmd2 colorama colored colorlog cryptography dnspython docutils enlighten entrypoints Flask future html5lib humanfriendly idna imagesize inflect ipparser itsdangerous keyring keyrings.alt ldap3 ldapdomaindump logutils lxml MarkupSafe multidict netaddr ntlm-auth packaging paramiko pbr Pillow pluginbase ply pockets prettytable prompt-toolkit psycopg2 psycopg2-binary pyasn1 pycparser pycrypto pycryptodomex pycurl Pygments PyGObject pymongo PyMySQL PyNaCl pyodbc pyOpenSSL pyparsing pyperclip pysmi pysnmp PySocks python-libnmap python-memcached pytz pyxdg PyYAML redis regex requests requests-ntlm requests-toolbelt SecretStorage selenium shodan six snowballstemmer soupsieve Sphinx sphinx-better-theme sphinxcontrib-napoleon sphinxcontrib-websupport SQLAlchemy SQLAlchemy-Utils stem stevedore tabulate termcolor tld tqdm urllib3 veryprettytable virtualenv virtualenv-clone virtualenvwrapper wcwidth webencodings Werkzeug yarl"

python3.6 -m pip FREEZE="$(python3.6 -m pip freeze)"
for lib in $LIBPY3; do
    if [[ ! "$(python3.6 -m pip FREEZE | grep -i "$lib")" = 0 ]]; then
        echo
        print_blue "[~] Install Python library ${lib} (py3)"
        python3.6 -m pip install "$lib"
    fi
done

print_delimiter

# -----------------------------------------------------------------------------
# Install Jython

if ! [ -x "$(command -v jython)" ]; then
    print_blue "[~] Install Jython"
    pacman -S --needed --noconfirm jython
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
    pacman -S --needed --noconfirm ruby
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

if [ -a /usr/local/rvm/scripts/rvm ]; then
    #shellcheck disable=SC1091
    source /usr/local/rvm/scripts/rvm
fi

if [ -n "$(command -v rvm)" ]; then
    print_blue "[~] Install Ruby RVM (Ruby Version Manager)"
    curl -sSL https://get.rvm.io | bash
    #shellcheck disable=SC1091
    source /etc/profile.d/rvm.sh
    if ! grep -q "source /etc/profile.d/rvm.sh" ~/.bashrc
    then
        echo "source /etc/profile.d/rvm.sh" >> ~/.bashrc
    fi
    # Make sure rvm will be available
    if ! grep -q "[[ -s /usr/share/rvm/scripts/rvm ]] && source /usr/share/rvm/scripts/rvm" ~/.bashrc
    then
        echo "[[ -s /usr/share/rvm/scripts/rvm ]] && source /usr/share/rvm/scripts/rvm" >> ~/.bashrc
    fi
    #shellcheck disable=SC1090
    source ~/.bashrc
    #shellcheck disable=SC1091
    source /usr/local/rvm/scripts/rvm
    if [ -n "$(command -v rvm)" ]; then
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

if [ -a /usr/local/rvm/scripts/rvm ]; then
    #shellcheck disable=SC1091
    source /usr/local/rvm/scripts/rvm
fi
if [[ ! "$(rvm list | grep -q "ruby-2.4.4")" = 0 ]]; then
    print_blue "[~] Install Ruby 2.4.4 (old version)"
    pacman -S --needed --noconfirm ruby-psych
    pacman -S --needed --noconfirm openssl
    rvm install ruby-2.4
    if [[ ! "$(rvm list | grep "ruby-2.4.4")" = 0 ]]; then
        print_red "[!] Ruby 2.4.4 has not been installed correctly with RVM"
        exit 1
    else
        rvm list
        print_green "[+] Ruby 2.4.4 has been successfully installed with RVM"
    fi
else
    print_green "[+] Ruby 2.4.4 is already installed"
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

if [[ ! "$(rvm list | grep -q "ruby-2.6.6")" = 0 ]]; then
    print_blue "[~] Install Ruby 2.6.6"
    rvm install ruby-2.6.6
    rvm --default use ruby-2.6.6
    gem install ffi
    if [[ ! "$(rvm list | grep "ruby-2.6.6")" = 0 ]]; then
        print_red "[!] Ruby 2.6.6 has not been installed correctly with RVM"
        exit 1
    else
        rvm list
        print_green "[+] Ruby 2.6.6 has been successfully installed with RVM"
    fi
else
    print_green "[+] Ruby 2.6.6 is already installed"
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
    pacman -S --needed --noconfirm perl
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
    pacman -S --needed --noconfirm php
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
# Install Java jdk8-openjdk

if ! [ -x "$(command -v jdk8-openjdk)" ]; then
    print_blue "[~] Install Java tools"
    pacman -S --needed --noconfirm jdk8-openjdk
    if [ -x "$(command -v jdk8-openjdk)" ]; then
        print_green "[+] Java jdk8-openjdk installed successfully"
    else
        print_red "[!] An error occured during Java jdk8-openjdk install"
        exit 1
    fi
else
    print_green "[+] Java jdk8-openjdk is already installed"
fi
print_delimiter

# ----------------------------------------------------------------------------
# Install Java jre8-openjdk

if ! [ -x "$(command -v jre8-openjdk)" ]; then
    print_blue "[~] Install Java tools jre8-openjdk"
    pacman -S --needed --noconfirm jre8-openjdk
    if [ -x "$(command -v jre8-openjdk)" ]; then
        print_green "[+] Java jre8-openjdk installed successfully"
    else
        print_red "[!] An error occured during Java jre8-openjdk install"
        exit 1
    fi
else
    print_green "[+] Java jre8-openjdk is already installed"
fi
print_delimiter

# ----------------------------------------------------------------------------
# Install Firefox

if ! [ -x "$(command -v firefox)" ]; then
    print_blue "[~] Install Firefox (for HTML reports and web screenshots)"
    pacman -S --needed --noconfirm firefox-esr
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
    cd /tmp/ || exit 1
    MACHINE_TYPE="$(uname -m)"
    if [ "$MACHINE_TYPE" == 'x86_64' ]; then
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

print_blue "[~] Install python3.6 libraries required by Jok3r (if missing)"
python3.6 -m pip install -r requirements.txt
python3.6 -m pip install --upgrade requests
print_delimiter

# -----------------------------------------------------------------------------

print_blue "[~] Disable UserWarning related to psycopg2"
python3.6 -m pip uninstall psycopg2-binary -y
python3.6 -m pip uninstall psycopg2 -y
python3.6 -m pip install psycopg2-binary
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
