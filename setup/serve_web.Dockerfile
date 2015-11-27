FROM grade_oven/grade_oven_base
RUN ["apt-get", "--assume-yes", "install", "python2.7", "python-flask", "python-openssl"]
USER grade_oven
