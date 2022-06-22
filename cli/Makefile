REV_COUNT = $(shell git rev-list --count HEAD)
COMMIT_DATE = $(shell git show -s --format=%cd --date=short HEAD)
REVISION = $(shell git rev-parse HEAD)
FLAGS = -gcflags "-l -l" -ldflags "-X main.RevCount=${REV_COUNT} -X main.Revision=${REVISION} -X main.CommitDate=${COMMIT_DATE} \
		-X 'main.goVersion=$(shell go version)'"
BINARY_SUFFIX :=

.PHONY: all
all: cli

vendor:
	go mod tidy

.PHONY: cli
cli: vendor
	go build ${FLAGS} -o bin/metaflow-ctl${BINARY_SUFFIX} cmd/ctl/main.go


.PHONY: clean
clean:
	rm -rf bin
