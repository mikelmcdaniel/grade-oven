FROM ubuntu
MAINTAINER Mikel Dmitri Mcdaniel
CMD ["echo", "You must pass a command to run explicitly."]
RUN ["apt-get", "--assume-yes", "update"]
RUN ["apt-get", "--assume-yes", "upgrade"]
# This is the volume that'll be used to interact with the host system
RUN ["mkdir", "/grade_oven"]
RUN ["useradd", "--comment", "Grade Oven", "--home", "/grade_oven", "--inactive", "-1", "--shell", "/bin/false", "grade_oven"]
RUN ["chmod", "755", "/grade_oven"]
RUN ["chown", "grade_oven:grade_oven", "/grade_oven"]

VOLUME ["/grade_oven"]
WORKDIR ["/grade_oven"]

# STOPSIGNAL SIGKILL

