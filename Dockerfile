# droplet

FROM centos:7.8.2003

MAINTAINER yuanchao@yunshan.net

RUN mkdir -p /etc/droplet/
COPY ./config/droplet.yaml /etc/droplet/
COPY ./bin/droplet /bin/
COPY start_docker.sh  /bin/

CMD /bin/start_docker.sh
