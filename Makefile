GOPATH = $(shell go env GOPATH)

verify: $(wildcard *.proto)
	protoc -I=. -I=${GOPATH}/src -I=${GOPATH}/src/github.com/gogo/protobuf/protobuf -o /dev/null $^

golang:
	mkdir -p alarm trident dfi zero
	chmod +w alarm trident dfi zero
	protoc --gofast_out=plugins=grpc:alarm -I. alarm.proto
	protoc --gofast_out=plugins=grpc:trident -I. trident.proto
	protoc -I=. -I=${GOPATH}/src -I=${GOPATH}/src/github.com/gogo/protobuf/protobuf --gogo_out=plugins=grpc:dfi dfi.proto
	protoc -I=. -I=${GOPATH}/src -I=${GOPATH}/src/github.com/gogo/protobuf/protobuf --gogo_out=plugins=grpc:zero zero.proto

all: golang

clean:
	git clean -dfx

.phony: all golang verify clean

.DEFAULT_GOAL := all
