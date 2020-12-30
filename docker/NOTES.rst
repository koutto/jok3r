
**Pull Docker image**
sudo docker pull koutto/jok3r

**Run fresh container**
sudo docker run -i -t --name jok3r-container -w /root/jok3r -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --shm-size 2g --net=host koutto/jok3r

On the host: xhost +local:root

**Run a stopped container**
sudo docker start -i jok3r-container

**Open a new shell inside a running container**
sudo docker exec -it jok3r-container bash