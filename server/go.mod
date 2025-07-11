module github.com/deepflowio/deepflow/server

go 1.24.0

toolchain go1.24.4

replace (
	cloud.google.com/go => cloud.google.com/go v0.103.0
	github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/expand => ./controller/cloud/kubernetes_gather/expand
	github.com/deepflowio/deepflow/server/controller/cloud/platform => ./controller/cloud/platform
	github.com/deepflowio/deepflow/server/controller/cloud/tencent/expand => ./controller/cloud/tencent/expand
	github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/edition => ./controller/db/metadb/migrator/edition
	github.com/deepflowio/deepflow/server/controller/genesis/store/sync => ./controller/genesis/store/sync
	github.com/deepflowio/deepflow/server/controller/http/appender => ./controller/http/appender
	github.com/deepflowio/deepflow/server/controller/http/service/agentlicense => ./controller/http/service/agentlicense
	github.com/deepflowio/deepflow/server/controller/http/service/configuration => ./controller/http/service/configuration
	github.com/deepflowio/deepflow/server/controller/monitor/license => ./controller/monitor/license
	github.com/deepflowio/deepflow/server/controller/monitor/vtap/version => ./controller/monitor/vtap/version
	github.com/deepflowio/deepflow/server/controller/native_field => ./controller/native_field
	github.com/deepflowio/deepflow/server/ingester/config/configdefaults => ./ingester/config/configdefaults
	github.com/deepflowio/deepflow/server/ingester/flow_log/log_data/dd_import => ./ingester/flow_log/log_data/dd_import
	github.com/deepflowio/deepflow/server/ingester/flow_log/log_data/sw_import => ./ingester/flow_log/log_data/sw_import
	github.com/deepflowio/deepflow/server/libs/logger/blocker => ./libs/logger/blocker
	github.com/deepflowio/deepflow/server/querier/app/distributed_tracing/service/tracemap => ./querier/app/distributed_tracing/service/tracemap
	github.com/deepflowio/deepflow/server/querier/app/prometheus/router/packet_adapter => ./querier/app/prometheus/router/packet_adapter
	github.com/deepflowio/deepflow/server/querier/app/prometheus/service/packet_wrapper => ./querier/app/prometheus/service/packet_wrapper
	github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/service/packet_service => ./querier/app/tracing-adapter/service/packet_service
	github.com/deepflowio/deepflow/server/querier/engine/clickhouse/packet_batch => ./querier/engine/clickhouse/packet_batch
	github.com/ionos-cloud/sdk-go/v6 => github.com/ionos-cloud/sdk-go/v6 v6.1.0
)

require (
	bou.ke/monkey v1.0.2
	github.com/ClickHouse/ch-go v0.65.1
	github.com/ClickHouse/clickhouse-go/v2 v2.1.0
	github.com/IBM/sarama v1.43.0
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/OneOfOne/xxhash v1.2.8
	github.com/Workiva/go-datastructures v1.0.53
	github.com/agiledragon/gomonkey/v2 v2.8.0
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1633
	github.com/aws/aws-sdk-go-v2 v1.17.3
	github.com/aws/aws-sdk-go-v2/config v1.17.8
	github.com/aws/aws-sdk-go-v2/credentials v1.12.21
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.63.1
	github.com/aws/aws-sdk-go-v2/service/eks v1.26.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.14.18
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.18.20
	github.com/baidubce/bce-sdk-go v0.9.141
	github.com/bitly/go-simplejson v0.5.0
	github.com/bxcodec/faker/v3 v3.8.0
	github.com/bytedance/sonic v1.12.5
	github.com/cornelk/hashmap v1.0.8
	github.com/deckarep/golang-set v1.8.0
	github.com/deckarep/golang-set/v2 v2.1.0
	github.com/deepflowio/deepflow/message v0.0.0-20240924113131-ec9660ac2e46
	github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/expand v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/cloud/platform v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/cloud/tencent/expand v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/edition v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/genesis/store/sync v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/http/appender v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/http/service/agentlicense v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/monitor/license v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/monitor/vtap/version v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/controller/native_field v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/ingester/config/configdefaults v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/ingester/flow_log/log_data/dd_import v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/ingester/flow_log/log_data/sw_import v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/libs/logger/blocker v0.0.0-20240822020041-cdaf0f82ce6f
	github.com/deepflowio/deepflow/server/querier/app/distributed_tracing/service/tracemap v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/querier/app/prometheus/router/packet_adapter v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/querier/app/prometheus/service/packet_wrapper v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/service/packet_service v0.0.0-00010101000000-000000000000
	github.com/deepflowio/deepflow/server/querier/engine/clickhouse/packet_batch v0.0.0-00010101000000-000000000000
	github.com/deepflowio/tempopb v0.0.0-20230215110519-15853baf3a79
	github.com/docker/go-units v0.4.0
	github.com/gin-gonic/gin v1.9.1
	github.com/go-redis/redis/v9 v9.0.0-rc.2
	github.com/go-sql-driver/mysql v1.8.1
	github.com/goccy/go-json v0.10.2
	github.com/gogo/protobuf v1.3.2
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.4
	github.com/golang/snappy v0.0.4
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.0
	github.com/grafana/pyroscope-go v1.2.0
	github.com/influxdata/influxdb v1.9.7
	github.com/jarcoal/httpmock v1.3.1
	github.com/jmoiron/sqlx v1.3.5
	github.com/klauspost/compress v1.17.11
	github.com/knadh/koanf/parsers/yaml v0.1.0
	github.com/knadh/koanf/providers/rawbytes v0.1.0
	github.com/knadh/koanf/v2 v2.1.2
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	github.com/lib/pq v1.10.2
	github.com/mark3labs/mcp-go v0.32.0
	github.com/mikioh/ipaddr v0.0.0-20190404000644-d465c8ab6721
	github.com/mitchellh/mapstructure v1.5.0
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/openshift/client-go v0.0.0-20210422153130-25c8450d1535
	github.com/orcaman/concurrent-map/v2 v2.0.1
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pebbe/zmq4 v1.2.9
	github.com/pkg/errors v0.9.1
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2
	github.com/prometheus/common v0.35.0
	github.com/prometheus/prometheus v0.36.2
	github.com/pyroscope-io/pyroscope v0.37.1
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/shirou/gopsutil/v3 v3.22.5
	github.com/smartystreets/goconvey v1.7.2
	github.com/spf13/cobra v1.4.0
	github.com/stretchr/testify v1.10.0
	github.com/swaggo/files v1.0.1
	github.com/swaggo/gin-swagger v1.6.0
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.0.726
	github.com/textnode/fencer v0.0.0-20121219195347-6baed0e5ef9a
	github.com/vishvananda/netlink v1.1.0
	github.com/volcengine/volcengine-go-sdk v1.0.141
	github.com/xwb1989/sqlparser v0.0.0-20180606152119-120387863bf2
	github.com/yuin/gopher-lua v1.1.1
	go.opentelemetry.io/collector/pdata v1.0.0
	go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin v0.49.0
	go.opentelemetry.io/otel v1.34.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.24.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.24.0
	go.opentelemetry.io/otel/sdk v1.34.0
	go.opentelemetry.io/otel/trace v1.34.0
	go.opentelemetry.io/proto/otlp v1.1.0
	golang.org/x/net v0.41.0
	golang.org/x/sync v0.15.0
	golang.org/x/sys v0.33.0
	google.golang.org/grpc v1.62.1
	google.golang.org/protobuf v1.36.5
	gopkg.in/alexcesaro/statsd.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/driver/mysql v1.3.4
	gorm.io/driver/postgres v1.5.11
	gorm.io/driver/sqlite v1.3.4
	gorm.io/gorm v1.25.10
	inet.af/netaddr v0.0.0-20211027220019-c74959edd3b6
	k8s.io/api v0.33.2
	k8s.io/apimachinery v0.33.2
	k8s.io/client-go v0.33.2
	sigs.k8s.io/yaml v1.4.0
	skywalking.apache.org/repo/goapi v0.0.0-20230712035303-201c1fb2d6ec
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/DataDog/zstd v1.4.1 // indirect
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/aws/aws-sdk-go v1.44.37 // indirect
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
	github.com/bytedance/sonic/loader v0.2.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudwego/base64x v0.1.4 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dennwc/varint v1.0.0 // indirect
	github.com/dgraph-io/badger/v2 v2.2007.2 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20190423205320-6a90982ecee2 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dmarkham/enumer v1.5.10 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/eapache/go-resiliency v1.6.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-faster/city v1.0.1 // indirect
	github.com/go-faster/errors v0.7.1 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.19.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/golang/glog v1.2.5 // indirect
	github.com/google/gnostic-models v0.6.9 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20190812055157-5d271430af9f // indirect
	github.com/grafana/pyroscope-go/godeltaprof v0.1.8 // indirect
	github.com/grafana/regexp v0.0.0-20220304095617-2e8d9baf4ac2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.19.1 // indirect
	github.com/hashicorp/consul/api v1.28.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/ionos-cloud/sdk-go/v6 v6.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.5.5 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jonboulle/clockwork v0.3.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lestrrat-go/strftime v1.0.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-sqlite3 v1.14.12 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/openshift/api v0.0.0-20210422150128-d8a48168c81c // indirect
	github.com/pascaldekloe/name v1.0.1 // indirect
	github.com/paulmach/orb v0.7.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_golang v1.12.2 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common/sigv4 v0.1.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/pyroscope-io/jfr-parser v0.5.2 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/smartystreets/assertions v1.2.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/swaggo/swag v1.8.12 // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	github.com/volcengine/volc-sdk-golang v1.0.23 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel/metric v1.34.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go4.org/intern v0.0.0-20211027215823-ae77deb06f29 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20231121144256-b99613f794b6 // indirect
	golang.org/x/arch v0.18.0 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/term v0.32.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.34.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240311132316-a219d84964c2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240314234333-6e1732d8331c // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250318190949-c8a335a9a2ff // indirect
	k8s.io/utils v0.0.0-20241104100929-3ea5e8cea738 // indirect
	sigs.k8s.io/json v0.0.0-20241010143419-9aa6b5e7a4b3 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.6.0 // indirect
)

replace github.com/deepflowio/deepflow/message => ../message
