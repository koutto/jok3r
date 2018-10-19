============
Installation
============

Docker
======
**The recommended way to use Jok3r is inside a Docker container so you will not have 
to worry about dependencies issues and installing the various hacking tools of the toolbox.**

.. image:: https://raw.githubusercontent.com/koutto/jok3r/master/pictures/docker-logo.png

A Docker image is available on Docker Hub and automatically re-built at each update: 
https://hub.docker.com/r/koutto/jok3r/. It is initially based on official Kali
Linux Docker image (kalilinux/kali-linux-docker).

.. image:: https://images.microbadger.com/badges/image/koutto/jok3r.svg
   :target: https://microbadger.com/images/koutto/jok3r
   :alt: Docker Image size


**Pull Jok3r Docker Image:**

.. code-block:: console

    sudo docker pull koutto/jok3r

**Run fresh Docker container:**

.. code-block:: console

    sudo docker run -i -t --name jok3r-container -w /root/jok3r koutto/jok3r

Jok3r and its toolbox is ready-to-use !

To re-run a stopped container:

.. code-block:: console

    sudo docker start -i jok3r-container


Manual install
==============

TODO
