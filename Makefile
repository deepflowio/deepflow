MESSAGE = gitlab.x.lan/yunshan/message
DROPLET_LIBS = gitlab.x.lan/yunshan/droplet-libs

REV_COUNT = $(shell git rev-list --count HEAD)
COMMIT_DATE = $(shell git show -s --format=%cd --date=short HEAD)
REVISION = $(shell git rev-parse HEAD)
FLAGS = -ldflags "-X main.RevCount=${REV_COUNT} -X main.Revision=${REVISION} -X main.CommitDate=${COMMIT_DATE}"

.PHONY: all
all: droplet droplet-ctl

vendor: patch/001-fix-afpacket-dirty-block.patch patch/002-record-logging-modules.patch
	go mod tidy && go mod vendor
	test -n "$(shell go list -e -f '{{.Dir}}' ${MESSAGE})"
	test -n "$(shell go list -e -f '{{.Dir}}' ${DROPLET_LIBS})"
	cp -r $(shell go list -e -f '{{.Dir}}' ${MESSAGE})/* vendor/${MESSAGE}/
	cp -r $(shell go list -e -f '{{.Dir}}' ${DROPLET_LIBS})/* vendor/${DROPLET_LIBS}/
	find vendor -type d -exec chmod +w {} \;
	cd vendor/${MESSAGE} && go generate ./...
	cd vendor/${DROPLET_LIBS} && go generate ./...
	cat patch/001-fix-afpacket-dirty-block.patch | patch -sN -d vendor/github.com/google/gopacket -p1
	cat patch/002-record-logging-modules.patch | patch -sN -d ./vendor/github.com/op/go-logging -p1

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

.PHONY: droplet-ctl
droplet-ctl: vendor
	go build -mod vendor ${FLAGS} -o bin/droplet-ctl cmd/droplet-ctl/main.go

.PHONY: clean
clean:
	git clean -dfx
