MESSAGE = gitlab.x.lan/yunshan/message

vendor:
	go mod download && go mod vendor
	cp -r $(shell go list -e -f '{{.Dir}}' ${MESSAGE})/* vendor/${MESSAGE}/
	make -C vendor/${MESSAGE}
	go generate ./geo/...
	go generate ./zerodoc/...

test: vendor
	go test -mod vendor -short ./... -coverprofile .test-coverage.txt

bench: vendor
	go test -mod vendor -bench=. ./...

clean:
	git clean -dfx

.DEFAULT_GOAL := test

.PHONY: test module bench clean
