.PHONY: all
all: querier

vendor:
	go generate ./...
	go mod tidy && go mod vendor

.PHONY: querier
querier: vendor
	go build -mod vendor -o bin/querier cmd/querier/main.go

.PHONY: clean
clean:
	touch vendor
	chmod -R 777 vendor
	rm -rf vendor
	rm -rf bin
