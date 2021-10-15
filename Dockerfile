# droplet
FROM docker.io/alpine

MAINTAINER yuanchao@yunshan.net

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add tzdata

RUN mkdir -p /etc/droplet/
COPY ./droplet.yaml /etc/droplet/
COPY ./bin/droplet /bin/
COPY ./bin/droplet-ctl /bin/
COPY start_docker.sh  /bin/

CMD /bin/start_docker.sh
