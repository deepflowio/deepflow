module:
	go mod download
	make -C $(shell go list -e -f '{{.Dir}}' gitlab.x.lan/yunshan/message)
	go generate ./geo/...
	go generate ./zerodoc/...

test: module
	go test -short ./... -coverprofile .test-coverage.txt

bench: module
	go test -bench=. ./...

clean:
	git clean -dfx

.DEFAULT_GOAL := test

.PHONY: test module bench clean
