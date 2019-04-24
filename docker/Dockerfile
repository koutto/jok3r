FROM kalilinux/kali-linux-docker

# NOTE: This Dockerfile is used to rebuild Jok3r Docker Image from scratch from
# kalilinux/kali-linux-docker. It is recommended to directly pull koutto/jok3r image instead

LABEL maintainer="xst3nz@gmail.com"
LABEL description="Docker Image for Jok3r - Network and Web Pentest Framework \
* Based on Kali Linux, \
* All dependencies installed, \
* All tools in toolbox installed."

# Will not prompt for questions
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /root

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y dist-upgrade && \
    apt-get install -y locales git gnupg2 && \
    echo 'export LC_ALL="en_US.UTF-8"' >> /root/.bashrc && \
    echo 'export LANG="en_US.UTF-8"' >> /root/.bashrc && \
    echo 'export LANGUAGE="en_US:en"' >> /root/.bashrc && \
    echo 'export PS1="\[$(tput bold)\]\[$(tput setaf 2)\]\u@jok3r-docker:\[$(tput setaf 4)\]\w\\$\[$(tput sgr0)\]\[$(tput sgr0)\] "' >> /root/.bashrc && \
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && \
    git clone https://github.com/koutto/jok3r.git 


# Add Sublime text for convenience for editing files if necessary
# Will require to run with the following arguments to use GUI
# sudo docker run -i -t -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix koutto/jok3r
# and on host: xhost +
RUN wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | apt-key add - && \
	apt-get install -y apt-transport-https && \
	echo "deb https://download.sublimetext.com/ apt/stable/" | tee /etc/apt/sources.list.d/sublime-text.list && \
	apt-get update && apt-get install -y sublime-text

# Set the locale
RUN locale-gen en_US.UTF-8  
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8  
ENV PYTHONIOENCODING utf-8

WORKDIR /root/jok3r

RUN ./install-all.sh


