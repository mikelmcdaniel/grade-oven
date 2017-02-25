#!/bin/bash
set -e  # exit on error

./mount.sh

sudo apt-get --assume-yes install python2.7 python-flask python-flask-login docker python-bcrypt python-leveldb authbind docker.io

sudo service docker start

# if the user grade oven does not exist *or* is not able to use docker
if ! groups gradeoven | grep docker; then
    sudo adduser gradeoven --disabled-password --disabled-login
    sudo adduser gradeoven docker
fi

sudo touch /etc/authbind/byport/443
sudo chown gradeoven:gradeoven /etc/authbind/byport/443
sudo chmod 755 /etc/authbind/byport/443

sudo docker build --build-arg GRADE_OVEN_UID="$(id -u gradeoven)" -t grade_oven/grade_oven -f grade_oven.Dockerfile --rm --memory-swap=-1 .



