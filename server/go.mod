module github.com/deepflowys/deepflow/server

go 1.18

replace (
	cloud.google.com/go => cloud.google.com/go v0.103.0
	github.com/deepflowys/deepflow/server/controller/cloud/platform => ./controller/cloud/platform
	github.com/deepflowys/deepflow/server/controller/monitor/license => ./controller/monitor/license
	github.com/ionos-cloud/sdk-go/v6 => github.com/ionos-cloud/sdk-go/v6 v6.1.0
)

require (
	bou.ke/monkey v1.0.2
	github.com/ClickHouse/clickhouse-go/v2 v2.1.0
	github.com/OneOfOne/xxhash v1.2.8
	github.com/Workiva/go-datastructures v1.0.53
	github.com/agiledragon/gomonkey/v2 v2.8.0
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1633
	github.com/baidubce/bce-sdk-go v0.9.123
	github.com/bitly/go-simplejson v0.5.0
	github.com/bxcodec/faker/v3 v3.8.0
	github.com/cactus/go-statsd-client/v5 v5.0.0
	github.com/deckarep/golang-set v1.8.0
	github.com/deepflowys/deepflow/message v0.0.0-20220801081713-147df8c43710
	github.com/deepflowys/deepflow/server/controller/cloud/platform v0.0.0-00010101000000-000000000000
	github.com/deepflowys/deepflow/server/controller/monitor/license v0.0.0-00010101000000-000000000000
	github.com/docker/go-units v0.4.0
	github.com/gin-contrib/pprof v1.3.0
	github.com/gin-gonic/gin v1.8.1
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.2
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/influxdata/influxdb v1.9.7
	github.com/jmoiron/sqlx v1.3.5
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	github.com/mikioh/ipaddr v0.0.0-20190404000644-d465c8ab6721
	github.com/olivere/elastic v6.2.37+incompatible
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/pebbe/zmq4 v1.2.9
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.35.0
	github.com/prometheus/prometheus v0.36.2
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/shirou/gopsutil/v3 v3.22.5
	github.com/smartystreets/goconvey v1.7.2
	github.com/spf13/cobra v1.4.0
	github.com/stretchr/testify v1.7.2
	github.com/textnode/fencer v0.0.0-20121219195347-6baed0e5ef9a
	github.com/vishvananda/netlink v1.1.0
	github.com/xwb1989/sqlparser v0.0.0-20180606152119-120387863bf2
	go.opentelemetry.io/proto/otlp v0.18.0
	golang.org/x/net v0.0.0-20220624214902-1bab6f366d9e
	golang.org/x/sys v0.0.0-20220624220833-87e55d714810
	google.golang.org/grpc v1.47.0
	gopkg.in/alexcesaro/statsd.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/driver/mysql v1.3.4
	gorm.io/driver/sqlite v1.3.4
	gorm.io/gorm v1.23.5
	inet.af/netaddr v0.0.0-20211027220019-c74959edd3b6
)

require (
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/aws/aws-sdk-go v1.44.20 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dennwc/varint v1.0.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/fortytw2/leaktest v1.3.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.10.0 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/goccy/go-json v0.9.7 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20190812055157-5d271430af9f // indirect
	github.com/grafana/regexp v0.0.0-20220304095617-2e8d9baf4ac2 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jonboulle/clockwork v0.3.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/lestrrat-go/strftime v1.0.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-sqlite3 v1.14.12 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/gomega v1.19.0 // indirect
	github.com/paulmach/orb v0.7.1 // indirect
	github.com/pelletier/go-toml/v2 v2.0.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_golang v1.12.2 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common/sigv4 v0.1.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/smartystreets/assertions v1.2.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.32.0 // indirect
	go.opentelemetry.io/otel v1.7.0 // indirect
	go.opentelemetry.io/otel/metric v0.30.0 // indirect
	go.opentelemetry.io/otel/trace v1.7.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/goleak v1.1.12 // indirect
	go4.org/intern v0.0.0-20211027215823-ae77deb06f29 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20211027215541-db492cf91b37 // indirect
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292 // indirect
	golang.org/x/oauth2 v0.0.0-20220622183110-fd043fe589d2 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20220224211638-0e9765cccd65 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220628213854-d9e0b6570c03 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/ini.v1 v1.66.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.70.0 // indirect
)
