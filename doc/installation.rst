============
Installation
============

Docker
======
**The recommended way to use Jok3r is inside a Docker container so you will not have 
to bother about dependencies and installing the whole toolbox.**

A Docker image is available and maintained on Docker Hub at 
https://hub.docker.com/r/koutto/jok3r-docker/. It is initially based on official Kali
Linux Docker image (kalilinux/kali-linux-docker).

**Pull Jok3r Docker Image**

.. code-block:: console

    sudo docker pull koutto/jok3r-docker

**Run fresh Docker container**

.. code-block:: console

    sudo docker run -i -t --name jok3r-container -w /root/jok3r koutto/jok3r-docker

Jok3r and its toolbox is ready-to-use !


Environment
===========
This project has been fully tested on **Kali Linux**, it should also work on other 
Debian-based systems.

You need to make sure you have **Python 3** installed to run *Jok3r*. 

The following tools must be installed to be able to run several security checks 
in *Jok3r* (installed by default on Kali Linux):

* Metasploit (msfconsole)
* Nmap

