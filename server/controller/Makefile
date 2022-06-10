MESSAGE = gitlab.yunshan.net/yunshan/metaflow/message
REV_COUNT = $(shell git rev-list --count HEAD)
COMMIT_DATE = $(shell git show -s --format=%cd --date=short HEAD)
REVISION = $(shell git rev-parse HEAD)
FLAGS = -gcflags "-l -l" -ldflags "-X main.RevCount=${REV_COUNT} -X main.Revision=${REVISION} -X main.CommitDate=${COMMIT_DATE} \
		-X 'main.goVersion=$(shell go version)'"
BINARY_SUFFIX :=

.PHONY: all
all: server

vendor:
	go generate ./...
	go mod tidy && go mod vendor
	test -n "$(shell go list -e -f '{{.Dir}}' ${MESSAGE})"
	cp -r $(shell go list -e -f '{{.Dir}}' ${MESSAGE})/* vendor/${MESSAGE}/
	find vendor -type d -exec chmod +w {} \;
	cd vendor/${MESSAGE} && go generate ./...

.PHONY: server
server: vendor
	go build -mod vendor ${FLAGS} -o bin/metaflow-server${BINARY_SUFFIX} cmd/server/controller/main.go
	go build -mod vendor ${FLAGS} -o bin/trisolaris-ctl${BINARY_SUFFIX} trisolaris/trisolarisctrl/main.go


.PHONY: clean
clean:
	touch vendor
	chmod -R 777 vendor
	rm -rf vendor
	rm -rf bin
