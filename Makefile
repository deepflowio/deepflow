GOPATH = $(shell go env GOPATH)
DROPLET_ROOT = ${GOPATH}/src/gitlab.x.lan/droplet

BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
COMMIT = $(shell git rev-list --count HEAD)-$(shell git rev-parse --short HEAD)
FLAGS = -ldflags "-X main.Branch=${BRANCH} -X main.Commit=${COMMIT}"

deps:
	[ -f ${GOPATH}/bin/dep ] || curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
	go get github.com/derekparker/delve/cmd/dlv
	go get github.com/golang/protobuf/protoc-gen-go
	mkdir -p ${GOPATH}/src/gitlab.x.lan/
	[ -d ${DROPLET_ROOT} ] || ln -snf ${CURDIR} ${DROPLET_ROOT}
	(cd ${DROPLET_ROOT}; dep ensure)

lint:
	go vet ./...

test:
	go test -short ./...

bench:
	go test -bench=. ./...

debug:
	go build ${FLAGS} -gcflags '-N -l' -o bin/droplet cmd/droplet/main.go

droplet:
	go build ${FLAGS} -o bin/droplet cmd/droplet/main.go

all: deps droplet

release: deps droplet

clean:
	git clean -dfx

.DEFAULT_GOAL := release

.PHONY: deps lint test droplet all release clean
