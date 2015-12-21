#!/bin/bash
set -e  # exit on error

sudo echo  # Used to get and cache sudo password quickly
docker build -t grade_oven/grade_oven -f grade_oven.Dockerfile --rm --memory-swap=-1 .
./mount.sh
