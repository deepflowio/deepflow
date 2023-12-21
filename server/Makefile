MESSAGE = github.com/deepflowio/deepflow/message
REV_COUNT = $(shell git rev-list --count HEAD)
COMMIT_DATE = $(shell git show -s --format=%cd --date=short HEAD)
REVISION = $(shell git rev-parse HEAD)
BRANCH = $(shell git branch  --show-current)
COMPILE_TIME= $(shell date +"%Y-%m-%d %H:%M:%S")
# build tags: [-tags=go-json] used for [gin-gonic/gin] marshal json
FLAGS = -gcflags "-l -l" -ldflags "-X main.Branch=${BRANCH} -X main.RevCount=${REV_COUNT} -X main.Revision=${REVISION} -X main.CommitDate=${COMMIT_DATE} \
		-X 'main.goVersion=$(shell go version)' -X 'main.CompileTime=${COMPILE_TIME}'" \
		-tags=go_json
BINARY_SUFFIX :=

.PHONY: all
all: server

generate_sources = $(shell find -not -path './vendor/*' -name '*.go.tmpl' -or -name '*.tmpldata')
generated_libs = libs/hmap/idmap/ubig_id_map.go libs/hmap/idmap/ubig_id_map_test.go \
		 libs/hmap/lru/ubig_lru.go libs/hmap/lru/ubig_lru_test.go \
		 libs/zerodoc/pooled_meters.go libs/kubernetes/watcher.gen.go

proto = vendor/${MESSAGE}/common/common.pb.go vendor/${MESSAGE}/trident/trident.pb.go vendor/${MESSAGE}/controller/controller.pb.go vendor/${MESSAGE}/alarm_event/alarm_event.pb.go libs/datatype/pb/flow_log.pb.go libs/zerodoc/pb/metric.pb.go libs/stats/pb/stats.pb.go

$(generated_libs): $(generate_sources)
	go generate ./...

vendor/${MESSAGE}/common/common.pb.go: vendor/${MESSAGE}/common.proto
	cd vendor/${MESSAGE} && go generate common/stub.go

vendor/${MESSAGE}/common.proto: vendor
	cp -r ../message/common.proto vendor/${MESSAGE}/
	cp -r ../message/common vendor/${MESSAGE}/

vendor/${MESSAGE}/trident/trident.pb.go: vendor/${MESSAGE}/trident.proto
	cd vendor/${MESSAGE} && go generate trident/stub.go

vendor/${MESSAGE}/trident.proto: vendor
	cp -r ../message/trident.proto vendor/${MESSAGE}/
	cp -r ../message/trident vendor/${MESSAGE}/

vendor/${MESSAGE}/controller/controller.pb.go: vendor/${MESSAGE}/controller.proto
	cd vendor/${MESSAGE} && go generate controller/stub.go

vendor/${MESSAGE}/controller.proto: vendor
	cp -r ../message/controller.proto vendor/${MESSAGE}/
	cp -r ../message/controller vendor/${MESSAGE}/

vendor/${MESSAGE}/alarm_event/alarm_event.pb.go: vendor/${MESSAGE}/alarm_event.proto
	cd vendor/${MESSAGE} && go generate alarm_event/stub.go

vendor/${MESSAGE}/alarm_event.proto: vendor
	cp -r ../message/alarm_event.proto vendor/${MESSAGE}/
	cp -r ../message/alarm_event vendor/${MESSAGE}/


libs/datatype/pb/flow_log.proto: vendor
	cp -r ../message/flow_log.proto libs/datatype/pb/
	# delete first 3 char of line 6-10 for go language
	sed -i '6,10s/^...//' libs/datatype/pb/flow_log.proto

libs/datatype/pb/flow_log.pb.go: libs/datatype/pb/flow_log.proto
	cd libs/datatype/pb && go generate ./...

libs/zerodoc/pb/metric.proto: vendor
	cp -r ../message/metric.proto libs/zerodoc/pb
	# delete first 3 char of line 6-10 for go language
	sed -i '6,10s/^...//' libs/zerodoc/pb/metric.proto

libs/zerodoc/pb/metric.pb.go: libs/zerodoc/pb/metric.proto
	cd libs/zerodoc/pb && go generate ./...

vendor/${MESSAGE}/stats.proto: vendor
	cp -r ../message/stats.proto vendor/${MESSAGE}/

libs/stats/pb/stats.pb.go: vendor/${MESSAGE}/stats.proto
	cp vendor/${MESSAGE}/stats.proto libs/stats/pb/stats.proto
	# delete first 3 char of line 6-10 for go language
	sed -i '6,10s/^...//' libs/stats/pb/stats.proto
	cd libs/stats/pb && go generate ./...

libs/geo/ip_info.go: libs/geo/ip_info_mini.json libs/geo/ip_info.py
	go generate ./...

vendor:
	go mod tidy && go mod download && go mod vendor
	find vendor -type d -exec chmod +w {} \;
	# optimize the write performance of Array(string) data type
	patch -p1 -d vendor/github.com/ClickHouse/clickhouse-go/v2/ < patch/clickhouse-go/write_improve.patch
	# reset the pointer to the nullable field
	patch -p1 -d vendor/github.com/ClickHouse/clickhouse-go/v2/ < patch/clickhouse-go/nullable.patch
	# optimize write datatime
	patch -p1 -d vendor/github.com/ClickHouse/clickhouse-go/v2/ < patch/clickhouse-go/datetime_uint32.patch
	# optimize the performance of hashmap when writing a large amount of data
	patch -p1 -d vendor/github.com/cornelk/hashmap < patch/cornelk_hashmap/perf.patch
	# hashmap support key [2]uint64
	patch -p1 -d vendor/github.com/cornelk/hashmap < patch/cornelk_hashmap/complex128.patch

.PHONY: test
test: vendor $(proto) $(generated_libs)
	go test -mod vendor -short ./... -timeout 5s -coverprofile .test-coverage.txt
	go tool cover -func=.test-coverage.txt

.PHONY: server
server: vendor $(proto) $(generated_libs)
	go build -mod vendor ${FLAGS} -o bin/deepflow-server${BINARY_SUFFIX} cmd/server/main.go cmd/server/config.go

.PHONY: querier
querier: vendor $(proto) $(generated_libs)
	go build -mod vendor ${FLAGS} -o bin/querier${BINARY_SUFFIX} querier/cmd/querier/main.go

.PHONY: clean
clean:
	touch vendor
	chmod -R 777 vendor
	rm -rf vendor
	rm -rf bin
	rm -rf .test-coverage.txt
	find . -name '*.pb.go' | grep -v libs/datatype/prompb/ | xargs -i rm -f {}
	rm -f libs/geo/ip_info.go
	rm -f $(generated_libs)
	rm -f libs/datatype/pb/flow_log.proto
	rm -f libs/zerodoc/pb/metric.proto
	rm -f libs/stats/pb/stats.proto
	rm -f libs/kubernetes/watcher.gen.go
