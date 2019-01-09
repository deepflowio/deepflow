GOPATH = $(shell go env GOPATH)
PROJECT_ROOT = ${GOPATH}/src/gitlab.x.lan/yunshan/droplet-libs

vendor:
	mkdir -p $(shell dirname ${PROJECT_ROOT})
	[ -d ${PROJECT_ROOT} ] || ln -snf ${CURDIR} ${PROJECT_ROOT}
	[ -f ${GOPATH}/bin/dep ] || curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
	(cd ${PROJECT_ROOT}; dep ensure)
	go generate ./vendor/gitlab.x.lan/yunshan/message/...
	go generate ./geo/...
	go generate ./zerodoc/...

test: vendor
	go test -short ./...

bench: vendor
	go test -bench=. ./...

clean:
	git clean -dfx

.DEFAULT_GOAL := test

.PHONY: test bench clean
