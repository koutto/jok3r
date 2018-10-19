FROM kalilinux/kali-linux-docker

WORKDIR /root

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y dist-upgrade && \
    apt-get install -y locales git && \
    echo 'export LC_ALL="en_US.UTF-8"' >> /root/.bashrc && \
    echo 'export LANG="en_US.UTF-8"' >> /root/.bashrc && \
    echo 'export LANGUAGE="en_US.UTF-8"' >> /root/.bashrc && \
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && locale-gen 


