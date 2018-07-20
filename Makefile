GOPATH = $(shell go env GOPATH)
DROPLET_LIBS_ROOT = ${GOPATH}/src/gitlab.x.lan/yunshan/droplet-libs

deps:
	[ -f ${GOPATH}/bin/dep ] || curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
	mkdir -p ${GOPATH}/src/gitlab.x.lan/yunshan/
	[ -d ${DROPLET_LIBS_ROOT} ] || ln -snf ${CURDIR} ${DROPLET_LIBS_ROOT}
	(cd ${DROPLET_LIBS_ROOT}; dep ensure)

format:
	(cd ${DROPLET_LIBS_ROOT}; go fmt ./...)

verify:
	(cd ${DROPLET_LIBS_ROOT}; go vet ./...)
	(cd ${DROPLET_LIBS_ROOT}; go test -short ./...)

.DEFAULT_GOAL := verify

.PHONY: deps format verify clean
