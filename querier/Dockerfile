FROM docker.io/alpine

MAINTAINER songzhen@yunshan.net

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add tzdata

COPY ./querier.yaml /etc/
COPY ./db_descriptions /etc/db_descriptions/
COPY ./bin/querier /bin/

CMD /bin/querier
