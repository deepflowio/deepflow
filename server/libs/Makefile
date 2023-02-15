MESSAGE = github.com/deepflowio/deepflow/message

vendor:
	go mod tidy && go mod download && go mod vendor
	test -n "$(shell go list -e -f '{{.Dir}}' ${MESSAGE})"
	cp -r $(shell go list -e -f '{{.Dir}}' ${MESSAGE})/* vendor/${MESSAGE}/
	#cp -f vendor/github.com/platform/influxdb/client/v2/* vendor/github.com/influxdata/influxdb/client/v2/
	find vendor -type d -exec chmod +w {} \;
	cd vendor/${MESSAGE}/ && go generate ./...
	# cd xdppacket/ebpf/; chmod a+x remote-make; ./remote-make
	go generate ./geo/...
	go generate ./zerodoc/...
	go generate ./datatype/...
	go generate ./hmap/lru/...
	go generate ./hmap/idmap/...

test: vendor
	go test -mod vendor -short ./... -timeout 30s -coverprofile .test-coverage.txt
	go tool cover -func=.test-coverage.txt

bench: vendor
	go test -mod vendor -bench=. ./...

clean:
	rm -rf vendor
	rm -rf bin
	rm -rf x86_64
	rm -rf zerodoc/pb/*.pb.go
	rm -rf datatype/pb/*.pb.go

.DEFAULT_GOAL := test

.PHONY: test module bench clean
