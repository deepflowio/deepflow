FROM alpine:latest as deepflow-server

MAINTAINER songzhen@yunshan.net

RUN apk update && \
    apk add --no-cache tzdata

COPY ./server.yaml /etc/
RUN mkdir -p /etc/metadb/schema
COPY ./controller/db/metadb/migrator/schema /etc/metadb/schema/
COPY ./controller/cloud/filereader/manual_data_samples.yaml /etc/
COPY ./querier/db_descriptions /etc/db_descriptions/
COPY ./controller/cloud/kubernetes_gather/lua /bin/
ARG TARGETARCH 

RUN --mount=target=/tmp-mount \
    cp -a /tmp-mount/bin/deepflow-server.${TARGETARCH} /bin/deepflow-server

CMD /bin/deepflow-server
