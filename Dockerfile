# droplet

FROM centos

MAINTAINER yuanchao@yunshan.net

COPY ./config/droplet.yaml /etc/
COPY ./bin/droplet /bin/

CMD /bin/droplet
