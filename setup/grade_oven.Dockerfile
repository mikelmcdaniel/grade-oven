FROM ubuntu
MAINTAINER Mikel Dmitri Mcdaniel
CMD ["echo", "You must pass a command to run explicitly."]
RUN ["apt-get", "--assume-yes", "update"]
RUN ["apt-get", "--assume-yes", "upgrade"]
RUN ["apt-get", "--assume-yes", "install", "unzip", "gzip", "tar"]
# This is the volume that'll be used to interact with the host system
RUN ["mkdir", "/grade_oven"]
RUN ["useradd", "--comment", "Grade Oven", "--home", "/grade_oven", "--inactive", "-1", "--shell", "/bin/false", "grade_oven"]
RUN ["chmod", "755", "/grade_oven"]
RUN ["chown", "grade_oven:grade_oven", "/grade_oven"]

VOLUME ["/grade_oven"]
WORKDIR ["/grade_oven"]

# Note that there is no "clang-format" package, but "clang-3.4" happens to be
# the latest version of clang in the repo as of 2015-11-27.
RUN ["apt-get", "--assume-yes", "install", "binutils", "clang", "make", "clang-format-3.4"]

USER grade_oven