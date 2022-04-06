.PHONY: all
all: querier

vendor:
	go generate ./...
	go mod tidy && go mod vendor

.PHONY: test
test: vendor
	go test -mod vendor -short ./... -timeout 5s -coverprofile .test-coverage.txt
	go tool cover -func=.test-coverage.txt

.PHONY: querier
querier: vendor
	go build -mod vendor -o bin/querier cmd/querier/main.go

.PHONY: clean
clean:
	touch vendor
	chmod -R 777 vendor
	rm -rf vendor
	rm -rf bin
	rm -rf .test-coverage.txt
