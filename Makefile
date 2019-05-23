MESSAGE = gitlab.x.lan/yunshan/message

vendor:
	go mod tidy && go mod download && go mod vendor
	test -n "$(shell go list -e -f '{{.Dir}}' ${MESSAGE})"
	cp -r $(shell go list -e -f '{{.Dir}}' ${MESSAGE})/* vendor/${MESSAGE}/
	find vendor -type d -exec chmod +w {} \;
	cd vendor/${MESSAGE}/ && go generate ./...
	go generate ./geo/...
	go generate ./zerodoc/...

test: vendor
	go test -mod vendor -short ./... -timeout 30s -coverprofile .test-coverage.txt
	go tool cover -func=.test-coverage.txt

bench: vendor
	go test -mod vendor -bench=. ./...

clean:
	git clean -dfx

.DEFAULT_GOAL := test

.PHONY: test module bench clean
