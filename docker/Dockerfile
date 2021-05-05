# Micro Backdoor Server
#
# VERSION 1.0

FROM ubuntu:18.04
MAINTAINER Cr4sh

ARG SSHD_PASS

# install neede packages
RUN apt-get update
RUN apt-get install -y swig libssl-dev python python-dev python-setuptools python-pip supervisor wget net-tools redis-server build-essential

# install python dependencies
RUN pip install --force-reinstall -U m2crypto pycrypto redis cherrypy defusedxml

# install ssh server
RUN apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo root:$SSHD_PASS | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# ssh login fix, otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

# set working directory
WORKDIR /opt/micro_backdoor_server

# copy server files
COPY server/ /opt/micro_backdoor_server/

# fix permissions
RUN find /opt/micro_backdoor_server -type f -print0 | xargs -0 chmod 600
RUN find /opt/micro_backdoor_server -type d -print0 | xargs -0 chmod 700

# copy supervisor config
COPY supervisord.conf /etc/supervisor/conf.d/

# run application
CMD [ "/usr/bin/supervisord" ]
