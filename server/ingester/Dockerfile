FROM golang:1.18.0 as builder
# ENV CGO_ENABLED=0
ENV GOPROXY=https://proxy.golang.com.cn,direct
# 还可以设置不走 proxy 的私有仓库或组，多个用逗号相隔（可选）
ENV  GOPRIVATE=github.com
RUN  sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list  && \
     sed -i 's|security.debian.org/debian-security|mirrors.aliyun.com/debian-security|g' /etc/apt/sources.list && \
     apt update && \
     apt -y install unzip tmpl pip && \
     ln  -s /usr/bin/python3.9 /usr/bin/python -f && \
     python -m pip install --user  --trusted-host mirrors.aliyun.com  --index-url https://mirrors.aliyun.com/pypi/simple/  ujson==1.35 && \
     wget http://nexus.yunshan.net/repository/tools/deepflow/protoc-3.6.1-linux-$(arch|sed 's|64|_64|g'|sed 's|__|_|g').zip && \
     unzip -d /usr/ protoc-3.6.1-linux-* && \
     rm protoc-3.6.1-linux-*
COPY . /droplet
WORKDIR /droplet
RUN  make clean && \
     go mod tidy && \
     mkdir -p /go/src/github.com/gogo/protobuf/ && \
     cp  -a /go/pkg/mod/github.com/gogo/protobuf*/*  /go/src/github.com/gogo/protobuf/ && \
     go install github.com/golang/protobuf/protoc-gen-go@v1.3.2 && \
     go install github.com/gogo/protobuf/protoc-gen-gofast@v1.3.2 && \
     go install github.com/gogo/protobuf/protoc-gen-gogo@v1.3.2 && \
     go get -u  github.com/gogo/protobuf/gogoproto@v1.3.2 && \
     go get github.com/gogo/protobuf && \
     make

# droplet
FROM docker.io/alpine

MAINTAINER yuanchao@yunshan.net

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add tzdata

RUN mkdir -p /etc/droplet/
COPY ./droplet.yaml /etc/droplet/
COPY --from=builder /droplet/bin/droplet /bin/
COPY --from=builder /droplet/bin/droplet-ctl /bin/
COPY start_docker.sh  /bin/

CMD /bin/start_docker.sh
