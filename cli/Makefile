MESSAGE = github.com/deepflowio/deepflow/message
LIBS = github.com/deepflowio/deepflow/server/libs
SERVER = github.com/deepflowio/deepflow/server
SERVER_LIBS = ../server/libs
MSG = ../message/
REV_COUNT = $(shell git rev-list --count HEAD)
COMMIT_DATE = $(shell git show -s --format=%cd --date=short HEAD)
REVISION = $(shell git rev-parse HEAD)
BRANCH = $(shell git branch  --show-current)
COMPILE_TIME= $(shell date +"%Y-%m-%d %H:%M:%S")
FLAGS = -gcflags "-l -l" -ldflags "-X main.RevCount=${REV_COUNT} -X main.Revision=${REVISION} -X main.CommitDate=${COMMIT_DATE} \
		-X 'main.goVersion=$(shell go version)' -X main.Branch=${BRANCH} -X 'main.CompileTime=${COMPILE_TIME}'"
BINARY_SUFFIX :=

.PHONY: all
all: cli

vendor:
	cp ${MSG}/metric.proto ${SERVER_LIBS}/flow-metrics/pb
	cp ${MSG}/flow_log.proto ${SERVER_LIBS}/datatype/pb
	cp ${MSG}/stats.proto ${SERVER_LIBS}/stats/pb
	sed -i '6,10s/^...//' ${SERVER_LIBS}/flow-metrics/pb/metric.proto
	sed -i '6,10s/^...//' ${SERVER_LIBS}/datatype/pb/flow_log.proto
	sed -i '6,10s/^...//' ${SERVER_LIBS}/stats/pb/stats.proto
	cd ${SERVER_LIBS}/ && go generate ./...
	go mod tidy && go mod download && go mod vendor
	cp -r ${MSG}/* vendor/${MESSAGE}/
	find vendor -type d -exec chmod +w {} \;
	cd vendor/${MESSAGE} && go generate ./...
	rm -rf ${MSG} && cp -r vendor/${MESSAGE} ${MSG} && go mod vendor
	patch -p1 -d vendor/github.com/ClickHouse/clickhouse-go/v2/ < ../server/patch/clickhouse-go/write_improve.patch
	patch -p1 -d vendor/github.com/cornelk/hashmap < ../server/patch/cornelk_hashmap/complex128.patch

.PHONY: cli
cli: vendor
	go generate ./...
	go build -mod vendor ${FLAGS} -o bin/deepflow-ctl${BINARY_SUFFIX} cmd/ctl/main.go

.PHONY: clean
clean:
	touch vendor
	chmod -R 777 vendor
	rm -rf vendor
	rm -rf ctl/common/*_string.go
	rm -rf bin
