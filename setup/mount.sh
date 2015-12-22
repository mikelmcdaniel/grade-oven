#!/bin/bash
for d in ../data/host_dirs/{0,1,2,3}; do
  mkdir -p "$d"
  sudo umount -t tmpfs "$d";
  sudo mount -t tmpfs -o size=64m,nr_inodes=50,mode=0700,nodev,rw tmpfs "$d";
  sudo chown ${USER}:${USER} "$d"
done
