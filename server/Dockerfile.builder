FROM golang:1.20-alpine

RUN apk update && \
    apk add protoc python3 py3-ujson make git
RUN go install github.com/gogo/protobuf/protoc-gen-gofast@v1.3.2 && \
    go install github.com/gogo/protobuf/protoc-gen-gogo@v1.3.2 && \
    go install github.com/benbjohnson/tmpl@v1.1.0
