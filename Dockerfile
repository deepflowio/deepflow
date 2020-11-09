# droplet

FROM centos:7.8.2003

MAINTAINER yuanchao@yunshan.net

RUN yum install -y epel-release && yum install -y zeromq

RUN mkdir -p /etc/droplet/
COPY ./droplet.yaml /etc/droplet/
COPY ./bin/droplet /bin/
COPY ./bin/droplet-ctl /bin/
COPY start_docker.sh  /bin/

CMD /bin/start_docker.sh
