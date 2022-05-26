FROM dfcloud-image-registry.cn-beijing.cr.aliyuncs.com/dev/alpine:latest

MAINTAINER songzhen@yunshan.net

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add tzdata

COPY ./querier.yaml /etc/
COPY ./db_descriptions /etc/db_descriptions/
ARG TARGETARCH

RUN --mount=target=/tmp-mount \
    cp -a /tmp-mount/bin/querier.${TARGETARCH} /bin/querier

CMD /bin/querier
