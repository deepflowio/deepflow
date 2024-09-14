FROM alpine:latest as deepflow-server

MAINTAINER songzhen@yunshan.net

RUN mkdir /etc/mysql
RUN apk update && \
    apk upgrade && \
    apk add tzdata
RUN useradd -u 1000 -m deepflow -s /bin/sh && \
    echo 'root:deepflow' | chpasswd

COPY ./server.yaml /etc/
COPY ./controller/db/mysql/migration/rawsql /etc/mysql
COPY ./controller/cloud/filereader/manual_data_samples.yaml /etc/
COPY ./querier/db_descriptions /etc/db_descriptions/
ARG TARGETARCH 

RUN --mount=target=/tmp-mount \
    cp -a /tmp-mount/bin/deepflow-server.${TARGETARCH} /bin/deepflow-server
RUN chown -R deepflow /etc/ /bin/deepflow-server

USER deepflow

CMD /bin/deepflow-server
