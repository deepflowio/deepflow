module github.com/deepflowio/deepflow/server

go 1.18

replace (
	cloud.google.com/go => cloud.google.com/go v0.103.0
	github.com/deepflowio/deepflow/server/controller/cloud/platform => ./controller/cloud/platform
	github.com/deepflowio/deepflow/server/controller/db/mysql/migrator => ./controller/db/mysql/migrator
	github.com/deepflowio/deepflow/server/controller/http/service/configuration => ./controller/http/service/configuration
	github.com/deepflowio/deepflow/server/controller/monitor/license => ./controller/monitor/license
	github.com/deepflowio/deepflow/server/querier/engine/clickhouse/packet_batch => ./querier/engine/clickhouse/packet_batch
	github.com/ionos-cloud/sdk-go/v6 => github.com/ionos-cloud/sdk-go/v6 v6.1.0
)

require (
	github.com/ClickHouse/clickhouse-go/v2 v2.1.0
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/OneOfOne/xxhash v1.2.8
	github.com/Workiva/go-datastructures v1.0.53
	github.com/agiledragon/gomonkey/v2 v2.8.0
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1633
	github.com/aws/aws-sdk-go-v2/config v1.17.8
	github.com/aws/aws-sdk-go-v2/credentials v1.12.21
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.63.1
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.14.18
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.18.20
	github.com/baidubce/bce-sdk-go v0.9.141
	github.com/bitly/go-simplejson v0.5.0
	github.com/bxcodec/faker/v3 v3.8.0
	github.com/deckarep/golang-set v1.8.0
	github.com/deckarep/golang-set/v2 v2.1.0
	github.com/deepflowio/deepflow/message v0.0.0-20230301103050-1946b9bb5067
	github.com/deepflowio/deepflow/server/controller/cloud/platform v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/db/mysql/migrator v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/http/service/configuration v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/monitor/license v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/querier/engine/clickhouse/packet_batch v0.0.0-00010101000000-000000000000
	github.com/deepflowio/tempopb v0.0.0-20230215110519-15853baf3a79
	github.com/docker/go-units v0.4.0
	github.com/gin-gonic/gin v1.8.1
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
	github.com/openshift/api v0.0.0-20210422150128-d8a48168c81c // indirect
	github.com/openshift/client-go v0.0.0-20210422153130-25c8450d1535
	github.com/pebbe/zmq4 v1.2.9
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.35.0
	github.com/prometheus/prometheus v0.36.2
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/shirou/gopsutil/v3 v3.22.5
	github.com/signalfx/splunk-otel-go/instrumentation/github.com/jmoiron/sqlx/splunksqlx v1.3.1
	github.com/smartystreets/goconvey v1.7.2
	github.com/spf13/cobra v1.4.0
	github.com/stretchr/testify v1.8.1
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.0.479
	github.com/textnode/fencer v0.0.0-20121219195347-6baed0e5ef9a
	github.com/vishvananda/netlink v1.1.0
	github.com/xwb1989/sqlparser v0.0.0-20180606152119-120387863bf2
	go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin v0.36.3
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.13.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.7.0
	go.opentelemetry.io/otel/sdk v1.13.0
	go.opentelemetry.io/proto/otlp v0.19.0
	golang.org/x/net v0.7.0
	golang.org/x/sys v0.5.0
	google.golang.org/grpc v1.53.0
	gopkg.in/alexcesaro/statsd.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/driver/mysql v1.3.4
	gorm.io/driver/sqlite v1.3.4
	gorm.io/gorm v1.23.5
	inet.af/netaddr v0.0.0-20211027220019-c74959edd3b6
	k8s.io/api v0.24.0
	k8s.io/apimachinery v0.24.0
	k8s.io/client-go v0.24.0
)

require (
	github.com/aws/aws-sdk-go-v2/service/eks v1.26.0
	github.com/go-redis/redis/v9 v9.0.0-rc.2
	github.com/pyroscope-io/pyroscope v0.37.1
)

require (
	github.com/DataDog/zstd v1.4.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.0 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/dgraph-io/badger/v2 v2.2007.2 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20190423205320-6a90982ecee2 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/fortytw2/leaktest v1.3.0 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.10.2 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/ionos-cloud/sdk-go/v6 v6.1.0 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/pyroscope-io/jfr-parser v0.5.2 // indirect
	github.com/signalfx/splunk-otel-go v1.3.1 // indirect
	github.com/signalfx/splunk-otel-go/instrumentation/database/sql/splunksql v1.3.1 // indirect
	github.com/signalfx/splunk-otel-go/instrumentation/internal v1.3.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.13.0 // indirect
	golang.org/x/exp v0.0.0-20230129154200-a960b3787bd2 // indirect
)

require (
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/aws/aws-sdk-go v1.44.37 // indirect
	github.com/aws/aws-sdk-go-v2 v1.17.3
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.19 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dennwc/varint v1.0.0 // indirect
	github.com/emicklei/go-restful v2.14.2+incompatible // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.6 // indirect
	github.com/go-openapi/swag v0.21.1 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.10.0 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/goccy/go-json v0.9.7 // indirect
	github.com/golang/snappy v0.0.4
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20190812055157-5d271430af9f // indirect
	github.com/grafana/regexp v0.0.0-20220304095617-2e8d9baf4ac2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
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
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f // indirect
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
	go.opentelemetry.io/otel v1.13.0
	go.opentelemetry.io/otel/metric v0.31.0 // indirect
	go.opentelemetry.io/otel/trace v1.13.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/goleak v1.1.12 // indirect
	go4.org/intern v0.0.0-20211027215823-ae77deb06f29 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20211027215541-db492cf91b37 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/oauth2 v0.4.0 // indirect
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4 // indirect
	golang.org/x/term v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/time v0.0.0-20220224211638-0e9765cccd65 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230209215440-0dfe4f8abfcc // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.66.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.70.0 // indirect
	k8s.io/kube-openapi v0.0.0-20220328201542-3ee0da9b0b42 // indirect
	k8s.io/utils v0.0.0-20220210201930-3a6ce19ff2f9 // indirect
	sigs.k8s.io/json v0.0.0-20211208200746-9f7c6b3444d2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
