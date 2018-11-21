GOPATH = $(shell go env GOPATH)
PROJECT_ROOT = ${GOPATH}/src/gitlab.x.lan/yunshan/droplet

REV_COUNT = $(shell git rev-list --count HEAD)
COMMIT_DATE = $(shell git show -s --format=%cd --date=short HEAD)
REVISION = $(shell git rev-parse HEAD)
FLAGS = -ldflags "-X main.RevCount=${REV_COUNT} -X main.Revision=${REVISION} -X main.CommitDate=${COMMIT_DATE}"

all: droplet droplet-ctl

vendor:
	mkdir -p $(shell dirname ${PROJECT_ROOT})
	[ -d ${PROJECT_ROOT} ] || ln -snf ${CURDIR} ${PROJECT_ROOT}
	[ -f ${GOPATH}/bin/dep ] || curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
	(cd ${PROJECT_ROOT}; dep ensure)
	go generate ./vendor/gitlab.x.lan/yunshan/message/...
	go generate ./vendor/gitlab.x.lan/yunshan/droplet-libs/...

test: vendor
	go test -short ./... -timeout 5s

bench: vendor
	go test -bench=. ./...

debug: vendor
	go build ${FLAGS} -gcflags 'all=-N -l' -o bin/droplet cmd/droplet/main.go

droplet: vendor
	go build ${FLAGS} -o bin/droplet cmd/droplet/main.go

droplet-ctl: vendor
	go build ${FLAGS} -o bin/droplet-ctl cmd/droplet-ctl/main.go

clean:
	git clean -dfx

.PHONY: droplet droplet-ctl test clean
