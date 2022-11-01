FROM alpine:latest as deepflow-server

MAINTAINER songzhen@yunshan.net

RUN apk add tzdata

COPY ./server.yaml /etc/
RUN mkdir /etc/mysql
COPY ./controller/db/mysql/migration/rawsql /etc/mysql
COPY ./controller/cloud/filereader/manual_data_samples.yaml /etc/
COPY ./querier/db_descriptions /etc/db_descriptions/
ARG TARGETARCH 

RUN --mount=target=/tmp-mount \
    cp -a /tmp-mount/bin/deepflow-server.${TARGETARCH} /bin/deepflow-server

CMD /bin/deepflow-server
