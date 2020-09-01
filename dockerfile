# droplet

FROM centos

MAINTAINER yuanchao@yunshan.net

COPY droplet /bin/
COPY droplet.yaml /etc/
CMD /bin/droplet
