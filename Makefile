GOPATH = $(shell go env GOPATH)
PROJECT_ROOT = ${GOPATH}/src/gitlab.x.lan/yunshan/droplet

REV_COUNT = $(shell git rev-list --count HEAD)
COMMIT_DATE = $(shell git show -s --format=%cd --date=short HEAD)
REVISION = $(shell git rev-parse HEAD)
FLAGS = -ldflags "-X main.RevCount=${REV_COUNT} -X main.Revision=${REVISION} -X main.CommitDate=${COMMIT_DATE}"

all: droplet droplet-ctl

vendor: patch/001-fix-afpacket-dirty-block.patch
	mkdir -p $(dir ${PROJECT_ROOT})
	[ -d ${PROJECT_ROOT} ] || ln -snf ${CURDIR} ${PROJECT_ROOT}
	[ -f ${GOPATH}/bin/dep ] || curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
	(cd ${PROJECT_ROOT}; dep ensure)
	go generate ./vendor/gitlab.x.lan/yunshan/droplet-libs/...
	cat $^ | patch -d ./vendor/github.com/google/gopacket -p1

PROTOBUF_FILES = $(addprefix vendor/gitlab.x.lan/yunshan/message/,dfi/dfi.pb.go zero/zero.pb.go trident/trident.pb.go)
${PROTOBUF_FILES}: vendor
	go generate ./vendor/gitlab.x.lan/yunshan/message/...

deps: vendor ${PROTOBUF_FILES}

test: deps
	go test -short ./... -timeout 5s -coverprofile .test-coverage.txt

bench: deps
	go test -bench=. ./...

debug: deps
	go build ${FLAGS} -gcflags 'all=-N -l' -o bin/droplet cmd/droplet/main.go

droplet: deps
	go build ${FLAGS} -o bin/droplet cmd/droplet/main.go

droplet-ctl: deps
	go build ${FLAGS} -o bin/droplet-ctl cmd/droplet-ctl/main.go

clean:
	git clean -dfx

.PHONY: droplet droplet-ctl deps test bench clean
