# droplet

FROM centos

MAINTAINER yuanchao@yunshan.net

RUN mkdir -p /etc/droplet/
COPY ./config/droplet.yaml /etc/droplet/
COPY ./bin/droplet /bin/

CMD /bin/droplet -f /etc/droplet/droplet.yaml
