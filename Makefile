MESSAGE = gitlab.yunshan.net/yunshan/message
DROPLET_LIBS = gitlab.yunshan.net/yunshan/droplet-libs

REV_COUNT = $(shell git rev-list --count HEAD)
COMMIT_DATE = $(shell git show -s --format=%cd --date=short HEAD)
REVISION = $(shell git rev-parse HEAD)
FLAGS = -gcflags "-l -l" -ldflags "-X main.RevCount=${REV_COUNT} -X main.Revision=${REVISION} -X main.CommitDate=${COMMIT_DATE} \
		-X 'main.goVersion=$(shell go version)' \
                -linkmode 'external' -extldflags '-static'"

.PHONY: all
all: droplet droplet-ctl

vendor:
	go generate ./...
	go mod tidy && go mod vendor
	test -n "$$(go list -e -f '{{.Dir}}' ${MESSAGE})"
	test -n "$$(go list -e -f '{{.Dir}}' ${DROPLET_LIBS})"
	cp -r $$(go list -e -f '{{.Dir}}' ${MESSAGE})/* vendor/${MESSAGE}/
	cp -r $$(go list -e -f '{{.Dir}}' ${DROPLET_LIBS})/* vendor/${DROPLET_LIBS}/
	find vendor -type d -exec chmod +w {} \;
	cd vendor/${MESSAGE} && go generate ./...
	cd vendor/${DROPLET_LIBS} && go generate ./...
	go generate ./...
	# 修复clickhouse-go的WritexxxNullable接口写入数据错误的问题
	patch vendor/github.com/ClickHouse/clickhouse-go/lib/data/block_write_column.go < patch/clickhouse-go/nullable.patch

.PHONY: test
test: vendor
	go test -mod vendor -short ./... -timeout 5s -coverprofile .test-coverage.txt
	go tool cover -func=.test-coverage.txt

.PHONY: bench
bench: vendor
	go test -mod vendor -bench=. ./...

.PHONY: debug
debug: vendor
	go build -mod vendor ${FLAGS} -gcflags 'all=-N -l' -o bin/droplet cmd/droplet/main.go

.PHONY: droplet
droplet: vendor
	go build -mod vendor ${FLAGS} -o bin/droplet cmd/droplet/main.go

es-tester: vendor
	go build -mod vendor ${FLAGS} -o bin/es-tester cmd/es-tester/main.go

.PHONY: droplet-ctl
droplet-ctl: vendor
	go build -mod vendor ${FLAGS} -o bin/droplet-ctl cmd/droplet-ctl/main.go

.PHONY: clean
clean:
	touch vendor
	chmod -R 777 vendor
	rm -rf vendor
	rm -rf bin
