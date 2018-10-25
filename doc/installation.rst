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

    sudo docker run -i -t --name jok3r-container -w /root/jok3r --net=host koutto/jok3r

**Important: --net=host option is required to share host's interface. It is needed for reverse
connections (e.g. Ping to container when testing for RCE, Get a reverse shell)**
Jok3r and its toolbox is ready-to-use !

To re-run a stopped container:

.. code-block:: console

    sudo docker start -i jok3r-container


Build your own Jok3r Docker Image
==================================
If you want to build your own Jok3r image from a fresh Kali image rather than use our pre-made one,
run the following commands:

.. code-block:: console
    
    wget https://raw.githubusercontent.com/koutto/jok3r/master/docker/Dockerfile
    sudo docker build -t jok3r-image .

.. note::
    For better convenience when editing files, *Sublime-text* editor is installed 
    inside Docker image. It is a GUI application, so you need to connect the container
    to host's X server to be able to run it:
    
    * Use the following command to run the container:

    .. code-block:: console
    
        sudo docker run -i -t --name jok3r-container -w /root/jok3r -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --net=host koutto/jok3r

    * On the host, execute the following command:

    .. code-block:: console
    
        xhost +local:root


Manual install
==============

TODO