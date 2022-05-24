FROM dfcloud-image-registry-vpc.cn-beijing.cr.aliyuncs.com/dev/golang:1.18.0 as builder
ENV CGO_ENABLED=0
ENV GOPROXY=https://proxy.golang.com.cn,direct
# 还可以设置不走 proxy 的私有仓库或组，多个用逗号相隔（可选）
ENV  GOPRIVATE=gitlab.yunshan.net
COPY . /querier
RUN cd /querier/  && make

FROM dfcloud-image-registry.cn-beijing.cr.aliyuncs.com/dev/alpine:latest

MAINTAINER songzhen@yunshan.net

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add tzdata

COPY ./querier.yaml /etc/
COPY ./db_descriptions /etc/db_descriptions/
COPY --from=builder /querier/bin/querier /bin/

CMD /bin/querier
