package config

import (
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/ingester/config"
)

var log = logging.MustGetLogger("exporters_config")

const (
	DefaultExportQueueCount = 4
	DefaultExportQueueSize  = 100000
	DefaultExportBatchSize  = 32
)

const (
	NETWORK_1M uint32 = 1 << iota
	NETWORK_MAP_1M
	APPLICATION_1M
	APPLICATION_MAP_1M
	NETWORK_1S
	NETWORK_MAP_1S
	APPLICATION_1S
	APPLICATION_MAP_1S

	PERF_EVENT

	L4_FLOW_LOG
	L7_FLOW_LOG

	MAX_DATASOURCE_ID
)

var DataSourceStringMap = map[string]uint32{
	"flow_metrics.network.1m":         NETWORK_1M,
	"flow_metrics.network_map.1m":     NETWORK_MAP_1M,
	"flow_metrics.application.1m":     APPLICATION_1M,
	"flow_metrics.application_map.1m": APPLICATION_MAP_1M,
	"flow_metrics.network.1s":         NETWORK_1S,
	"flow_metrics.network_map.1s":     NETWORK_MAP_1S,
	"flow_metrics.application.1s":     APPLICATION_1S,
	"flow_metrics.application_map.1s": APPLICATION_MAP_1S,
	"event.perf_event":                PERF_EVENT,
}

func StringsToDataSourceBits(strs []string) uint32 {
	ret := uint32(0)
	for _, str := range strs {
		t, ok := DataSourceStringMap[str]
		if !ok {
			log.Warningf("unknown export datasource: %s", str)
			continue
		}
		ret |= t
	}
	return ret
}

type Operator uint8

const (
	EQ Operator = iota
	NEQ
	IN
	NOT_IN
	WILDCARD_EQ
	WILDCARD_NEQ
	REGEXP_EQ
	REGEXP_NEQ

	MAX_OPERATOR_ID
)

var operatorStrings = [MAX_OPERATOR_ID]string{
	EQ:           "=",
	NEQ:          "!=",
	IN:           "in",
	NOT_IN:       "not in",
	WILDCARD_EQ:  ":",
	WILDCARD_NEQ: "!:",
	REGEXP_EQ:    "~",
	REGEXP_NEQ:   "!~",
}

func (o Operator) String() string {
	return operatorStrings[o]
}

type TagFilter struct {
	FieldName   string   `yaml:"field-name"`
	Operator    string   `yaml:"operator"`
	FieldValues []string `yaml:"field-values"`

	OperatorID   Operator
	ValueStrings []string
	ValueFloat64 []float64
}

type TranslateMap uint8

const (
	NONE uint8 = iota
	AUTO_INSTANCE_TYPE
	AUTO_SERVICE_TYPE
	CAPTURE_NIC_TYPE
	CLOSE_TYPE
	ETH_TYPE
	EVENT_LEVEL
	EVENT_SIGNAL_SOURCE
	EVENT_TYPE
	INSTANCE_TYPE
	IP_TYPE

	L7_PROTOCOL
)

var translateMapStrings = []string{
	NONE:               "none",
	AUTO_INSTANCE_TYPE: "auto_instance_type",
	AUTO_SERVICE_TYPE:  "auto_service_type",
	CAPTURE_NIC_TYPE:   "capture_nic_type",
	L7_PROTOCOL:        "l7_protocol",
}

type StructTags struct {
	// from struct tag
	Name           string // tag json
	Index          int
	Offset         uintptr
	Category       uint64 // tag category
	SubCategory    uint64 // tag sub
	DataType       reflect.Kind
	TranslateMapID uint8 // tag translate: , l7_protocol...
	UniversalTagID uint8 // region_id,az_id ...
	Omitempty      bool

	IsExport bool // check by ExportFields

	// from config TagFilters
	TagFilters []TagFilter
}

// ExporterCfg holds configs of different exporters.
type ExporterCfg struct {
	Protocol       string         `yaml:"protocol"`
	ExportProtocol ExportProtocol // gen by `Protocol`
	DataSources    []string       `yaml:"data-sources"`
	DataSourceBits uint32         // gen by `DataSources`
	Endpoints      []string       `yaml:"endpoints"`
	QueueCount     int            `yaml:"queue-count"`
	QueueSize      int            `yaml:"queue-size"`
	BatchSize      int            `yaml:"batch-size"`
	FlusTimeout    int            `yaml:"flush-timeout"`

	TagFilters              []TagFilter `yaml:"tag-filters"`
	ExportFields            []string    `yaml:"export-fields"`
	ExportFieldCategoryBits uint64      // gen by `ExportFields`
	ExportFieldNames        []string    // gen by `ExportFields`
	ExportFieldK8s          []string    // gen by `ExportFields`

	ExportFieldStructTags [MAX_DATASOURCE_ID][]StructTags // gen by `ExportFields` and init when exporting item first time
	TagFieltertStructTags [MAX_DATASOURCE_ID][]StructTags // gen by `TagFilters`  and init when exporting item first time

	// private configuration
	ExtraHeaders map[string]string `yaml:"extra-headers"`

	// for Otlp l7_flow_log exporter

	// for promemtheus

	// for kafka
}

type ExportProtocol uint8

const (
	PROTOCOL_OTLP ExportProtocol = iota
	PROTOCOL_PROMETHEUS
	PROTOCOL_KAFKA

	MAX_PROTOCOL_ID
)

var protocolToStrings = []string{
	PROTOCOL_OTLP:       "opentelemetry",
	PROTOCOL_PROMETHEUS: "promethes",
	PROTOCOL_KAFKA:      "kafka",
	MAX_PROTOCOL_ID:     "unknown",
}

func stringToExportProtocol(str string) ExportProtocol {
	for i, v := range protocolToStrings {
		if v == str {
			return ExportProtocol(i)
		}
	}
	log.Warningf("unsupport export protocol: %s", str)
	return MAX_PROTOCOL_ID
}

func (p ExportProtocol) String() string {
	return protocolToStrings[p]
}

func (cfg *ExporterCfg) Validate() error {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = DefaultExportBatchSize
	}

	if cfg.QueueCount == 0 {
		cfg.QueueCount = DefaultExportQueueCount
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = DefaultExportQueueSize
	}
	cfg.DataSourceBits = StringsToDataSourceBits(cfg.DataSources)
	cfg.ExportFieldCategoryBits = StringsToCategoryBits(cfg.ExportFields)
	cfg.ExportFieldNames = cfg.ExportFields
	cfg.ExportProtocol = stringToExportProtocol(cfg.Protocol)
	cfg.ExportFieldK8s = GetK8sLabelConfigs(cfg.ExportFields)
	return nil
}

type ExportersConfig struct {
	Exporters Config `yaml:"ingester"`
}

type Config struct {
	Base      *config.Config
	Exporters []ExporterCfg `yaml:"exporters"`
}

func (c *Config) Validate() error {
	for i := range c.Exporters {
		if err := c.Exporters[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

var DefaultOtlpExportCategory = []string{"service_info", "tracing_info", "network_layer", "flow_info", "transport_layer", "application_layer", "metrics"}

func bitsToString(bits uint64, strMap map[string]uint64) string {
	ret := ""
	for k, v := range strMap {
		if bits&v != 0 {
			if len(ret) == 0 {
				ret = k
			} else {
				ret = ret + "," + k
			}
		}
	}
	return ret
}

const (
	UNKNOWN_CATEGORY = 0

	TAG uint64 = 1 << iota
	FLOW_INFO
	CLIENT_UNIVERSAL_TAG
	SERVER_UNIVERSAL_TAG
	CLIENT_CUSTOM_TAG
	SERVER_CUSTOM_TAG
	NATIVE_TAG
	NETWORK_LAYER
	TUNNEL_INFO
	TRANSPORT_LAYER
	APPLICATION_LAYER
	SERVICE_INFO
	TRACING_INFO
	CAPTURE_INFO
	EVENT_INFO // perf_event only
	K8S_LABEL

	METRICS
	L3_THROUGHPUT // network*/l4_flow_log
	L4_THROUGHPUT // network*/l4_flow_log
	TCP_SLOW      // network*/l4_flow_log
	TCP_ERROR     // network*/l4_flow_log
	APPLICATION   // network*/l4_flow_log
	THROUGHPUT    // application*/l7_flow_log
	ERROR         // application*/l7_flow_log
	DELAY         // all
)

var categoryStringMap = map[string]uint64{
	"tag":                  TAG,
	"flow_info":            FLOW_INFO,
	"client_universal_tag": CLIENT_UNIVERSAL_TAG,
	"server_universal_tag": SERVER_UNIVERSAL_TAG,
	"client_custom_tag":    CLIENT_CUSTOM_TAG,
	"server_custom_tag":    SERVER_CUSTOM_TAG,
	"native_tag":           NATIVE_TAG,
	"network_layer":        NETWORK_LAYER,
	"tunnel_info":          TUNNEL_INFO,
	"transport_layer":      TRANSPORT_LAYER,
	"application_layer":    APPLICATION_LAYER,
	"service_info":         SERVICE_INFO,
	"tracing_info":         TRACING_INFO,
	"capture_info":         CAPTURE_INFO,
	"k8s_label":            K8S_LABEL,

	"metrics":       METRICS,
	"l3_throughput": L3_THROUGHPUT,
	"l4_throughput": L4_THROUGHPUT,
	"tcp_slow":      TCP_SLOW,
	"tcp_error":     TCP_ERROR,
	"application":   APPLICATION,
	"throughput":    THROUGHPUT,
	"error":         ERROR,
	"delay":         DELAY,
}

func StringsToCategoryBits(strs []string) uint64 {
	ret := uint64(0)
	for _, str := range strs {
		if !strings.HasPrefix(str, "@") {
			continue
		}
		t, ok := categoryStringMap[str]
		if !ok {
			log.Warningf("unknown export category: %s", str)
			continue
		}
		ret |= t
	}
	return ret
}

func GetK8sLabelConfigs(strs []string) []string {
	ret := []string{}
	for _, str := range strs {
		if strings.HasPrefix(str, "k8s") || strings.HasPrefix(str, "~k8s") {
			ret = append(ret, str)
		}
	}
	return ret
}

func CategoryBitsToString(bits uint64) string {
	return bitsToString(bits, categoryStringMap)
}

func Load(base *config.Config, path string) *Config {
	config := &ExportersConfig{
		Exporters: Config{
			Base: base,
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Exporters
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.Exporters.Validate()
		return &config.Exporters
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Exporters.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.Exporters
}
