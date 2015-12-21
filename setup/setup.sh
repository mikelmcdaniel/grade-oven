#!/bin/bash
set -e  # exit on error

docker build -t grade_oven/grade_oven -f grade_oven.Dockerfile --rm --memory-swap=-1 .

sudo apt-get --assume-yes install python2.7 python-flask python-flask-login docker python-bcrypt python-leveldb

./mount.sh
