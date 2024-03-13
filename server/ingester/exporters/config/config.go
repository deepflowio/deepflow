/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/IBM/sarama"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("exporters_config")

const (
	DefaultExportQueueCount     = 4
	DefaultExportQueueSize      = 100000
	DefaultExportOtlpBatchSize  = 32
	DefaultExportOtherBatchSize = 1024
	SecurityProtocol            = "SASL_SSL"

	CATEGORY_K8S_LABEL = "$k8s.label"
	CATEGORY_TAG       = "$tag"
	CATEGORY_METRICS   = "$metrics"
)

var DefaultExportCategory = []string{"$service_info", "$tracing_info", "$network_layer", "$flow_info", "$transport_layer", "$application_layer", "$metrics"}

type DataSourceID uint32

const (
	NETWORK_1M         = DataSourceID(flow_metrics.NETWORK_1M)
	NETWORK_MAP_1M     = DataSourceID(flow_metrics.NETWORK_MAP_1M)
	APPLICATION_1M     = DataSourceID(flow_metrics.APPLICATION_1M)
	APPLICATION_MAP_1M = DataSourceID(flow_metrics.APPLICATION_MAP_1M)
	NETWORK_1S         = DataSourceID(flow_metrics.NETWORK_1S)
	NETWORK_MAP_1S     = DataSourceID(flow_metrics.NETWORK_MAP_1S)
	APPLICATION_1S     = DataSourceID(flow_metrics.APPLICATION_1S)
	APPLICATION_MAP_1S = DataSourceID(flow_metrics.APPLICATION_MAP_1S)
)
const (
	PERF_EVENT = DataSourceID(flow_metrics.METRICS_TABLE_ID_MAX) + 1 + iota
	L4_FLOW_LOG
	L7_FLOW_LOG

	MAX_DATASOURCE_ID
)

var dataSourceStrings = []string{
	NETWORK_1M:         "flow_metrics.network.1m",
	NETWORK_MAP_1M:     "flow_metrics.network_map.1m",
	APPLICATION_1M:     "flow_metrics.application.1m",
	APPLICATION_MAP_1M: "flow_metrics.application_map.1m",
	NETWORK_1S:         "flow_metrics.network.1s",
	NETWORK_MAP_1S:     "flow_metrics.network_map.1s",
	APPLICATION_1S:     "flow_metrics.application.1s",
	APPLICATION_MAP_1S: "flow_metrics.application_map.1s",
	PERF_EVENT:         "event.perf_event",
	L4_FLOW_LOG:        "flow_log.l4_flow_log",
	L7_FLOW_LOG:        "flow_log.l7_flow_log",
	MAX_DATASOURCE_ID:  "invalid_datasource",
}

func FlowLogMessageToDataSourceID(messageType datatype.MessageType) uint32 {
	switch messageType {
	case datatype.MESSAGE_TYPE_TAGGEDFLOW:
		return uint32(L4_FLOW_LOG)
	case datatype.MESSAGE_TYPE_PROTOCOLLOG:
		return uint32(L7_FLOW_LOG)
	}
	return uint32(MAX_DATASOURCE_ID)
}

func ToDataSourceID(str string) (DataSourceID, error) {
	for i, v := range dataSourceStrings {
		if v == str {
			return DataSourceID(i), nil
		}
	}
	return MAX_DATASOURCE_ID, fmt.Errorf("invalid datasource %s", str)
}

func StringsToDataSourceBits(strs []string) uint32 {
	ret := uint32(0)
	for _, str := range strs {
		t, err := ToDataSourceID(str)
		if err != nil {
			log.Warningf("unknown export datasource: %s", str)
			continue
		}
		ret |= (1 << uint32(t))
	}
	return ret
}

func (d DataSourceID) String() string {
	return dataSourceStrings[d]
}

func (d DataSourceID) IsMap() bool {
	switch d {
	case NETWORK_1M, APPLICATION_1M, NETWORK_1S, APPLICATION_1S, PERF_EVENT:
		return false
	default:
		return true
	}
}

// 'n|nm|a|am' used to distinguish different datasources under flow metrics.*
func TagStringToDataSourceBits(s string) uint32 {
	ret := uint32(0)
	if s == "" {
		return 0
	}
	dss := strings.Split(s, "|")
	for _, ds := range dss {
		switch ds {
		case "n":
			ret |= 1 << uint32(NETWORK_1M)
			ret |= 1 << uint32(NETWORK_1S)
		case "nm":
			ret |= 1 << uint32(NETWORK_MAP_1M)
			ret |= 1 << uint32(NETWORK_MAP_1S)
		case "a":
			ret |= 1 << uint32(APPLICATION_1M)
			ret |= 1 << uint32(APPLICATION_1S)
		case "am":
			ret |= 1 << uint32(APPLICATION_MAP_1M)
			ret |= 1 << uint32(APPLICATION_MAP_1S)
		}
	}
	return ret
}

type OperatorID uint8

const (
	EQ OperatorID = iota
	NEQ
	IN
	NOT_IN
	WILDCARD_EQ
	WILDCARD_NEQ
	REGEXP_EQ
	REGEXP_NEQ

	INVALID_OPERATOR_ID
)

var operatorStrings = [INVALID_OPERATOR_ID]string{
	EQ:           "=",
	NEQ:          "!=",
	IN:           "in",
	NOT_IN:       "not in",
	WILDCARD_EQ:  ":",
	WILDCARD_NEQ: "!:",
	REGEXP_EQ:    "~",
	REGEXP_NEQ:   "!~",
}

func (o OperatorID) String() string {
	return operatorStrings[o]
}

func operatorStringToID(op string) OperatorID {
	for i, Operator := range operatorStrings {
		if Operator == strings.ToLower(op) {
			return OperatorID(i)
		}
	}
	log.Warningf("invalid operator(%s), support operators %v", op, operatorStrings[:INVALID_OPERATOR_ID])
	return INVALID_OPERATOR_ID
}

type TagFilter struct {
	FieldName   string   `yaml:"field-name"`
	Operator    string   `yaml:"operator"`
	FieldValues []string `yaml:"field-values"`

	FieldFloat64s  []float64
	OperatorId     OperatorID
	RegexpComplied *regexp.Regexp
}

func (t *TagFilter) Validate() {
	t.OperatorId = operatorStringToID(t.Operator)
	if t.OperatorId == EQ || t.OperatorId == NEQ || t.OperatorId == IN || t.OperatorId == NOT_IN {
		for _, str := range t.FieldValues {
			if float64Value, err := strconv.ParseFloat(str, 64); err != nil {
				t.FieldFloat64s = []float64{}
			} else {
				t.FieldFloat64s = append(t.FieldFloat64s, float64Value)
			}
		}
	} else if t.OperatorId == REGEXP_EQ || t.OperatorId == REGEXP_NEQ || t.OperatorId == WILDCARD_EQ || t.OperatorId == WILDCARD_NEQ {
		for _, str := range t.FieldValues {
			// when wildcard matching, '*' needs to be converted to '.*'
			if t.OperatorId == WILDCARD_EQ || t.OperatorId == WILDCARD_NEQ {
				str = strings.ReplaceAll(str, "*", ".*")
			}
			regCompiled, err := regexp.Compile(str)
			if err != nil {
				continue
			}
			t.RegexpComplied = regCompiled
			break
		}
	}
}

func strInSlice(strs []string, str string) bool {
	for _, v := range strs {
		if str == v {
			return true
		}
	}
	return false
}

func float64InSlice(floats []float64, float float64) bool {
	for _, v := range floats {
		if float == v {
			return true
		}
	}
	return false
}

func (t *TagFilter) MatchStringValue(value string) bool {
	switch t.OperatorId {
	case EQ, IN:
		return strInSlice(t.FieldValues, value)
	case NEQ, NOT_IN:
		return !strInSlice(t.FieldValues, value)
	case REGEXP_EQ, WILDCARD_EQ:
		if t.RegexpComplied != nil {
			return t.RegexpComplied.MatchString(value)
		}
	case REGEXP_NEQ, WILDCARD_NEQ:
		if t.RegexpComplied != nil {
			return !t.RegexpComplied.MatchString(value)
		}
	}
	return true
}

func (t *TagFilter) MatchFloatValue(value float64) bool {
	switch t.OperatorId {
	case EQ, IN:
		return float64InSlice(t.FieldFloat64s, value)
	case NEQ, NOT_IN:
		return !float64InSlice(t.FieldFloat64s, value)
	}
	return true
}

func (t *TagFilter) MatchValue(value interface{}) bool {
	var float64Value float64
	var isFloat64 bool
	strValue, isStr := value.(string)
	if !isStr {
		float64Value, isFloat64 = utils.ConvertToFloat64(value)
	}

	if !isStr && !isFloat64 {
		return true
	}

	if isStr {
		return t.MatchStringValue(strValue)
	} else if isFloat64 {
		return t.MatchFloatValue(float64Value)
	}
	return true
}

type StructTags struct {
	DataSourceID      uint32            // get from interface DataSource()
	Name              string            // tag: 'json'
	MapName           string            // tag: 'map_json'
	FieldName         string            // field name, get from reflect
	Offset            uintptr           // get from reflect
	Category          string            // tag: 'category'
	CategoryBit       uint64            // gen from tag: 'category'
	SubCategoryBit    uint64            // gen from tag: 'sub'
	ToStringFuncName  string            // tag: 'to_string'
	ToStringFunc      reflect.Value     // gen from 'to_string'
	DataKind          reflect.Kind      // get from reflect
	DataTypeStr       string            // tag: 'data_type'. if 'DataKind' cannot determine the field type, it uses 'DataType' to determine
	DataType          utils.DataType    // gen from 'DataTypeStr'
	EnumFile          string            // tag: 'enumfile': as l7_protocol, from server/querier/db_descriptions/clickhouse/tag/enum/*
	EnumIntMap        map[int]string    // gen from content of `EnumFile`
	EnumStringMap     map[string]string // gen from content of `EnumFile`
	UniversalTagMapID uint8             // gen from universal tags
	Omitempty         bool              // tag: 'omitempty', not support yet
	TagDataSourceStr  string            // tag: 'datasource'
	TagDataSourceBits uint32            // gen from 'TagDatasourceStr'

	// the field has tagFilter, if it is not nil, should caculate filter
	TagFilters []TagFilter // gen from 'ExporterCfg.TagFilters'

	IsExportedField bool // gen from 'ExporterCfg.ExportFields'
}

// ExporterCfg holds configs of different exporters.
type ExporterCfg struct {
	Protocol        string         `yaml:"protocol"`
	Enabled         bool           `yaml:"enabled"`
	ExportProtocol  ExportProtocol // gen by `Protocol`
	DataSources     []string       `yaml:"data-sources"`
	DataSourceBits  uint32         // gen by `DataSources`
	Endpoints       []string       `yaml:"endpoints"`
	RandomEndpoints []string       // gen by `Endpoints`     `

	QueueCount                   int  `yaml:"queue-count"`
	QueueSize                    int  `yaml:"queue-size"`
	BatchSize                    int  `yaml:"batch-size"`
	FlusTimeout                  int  `yaml:"flush-timeout"`
	TagOmitemptyDisabled         bool `yaml:"tag-omitempty-disabled"`
	MetricsOmitempty             bool `yaml:"metrics-omitempty"`
	EnumToStringDisabled         bool `yaml:"enum-to-string-disabled"`
	UniversalTagToStringDisabled bool `yaml:"universal-tag-to-string-disabled"`

	TagFilters              []TagFilter `yaml:"tag-filters"`
	ExportFields            []string    `yaml:"export-fields"`
	ExportFieldCategoryBits uint64      // gen by `ExportFields`
	ExportFieldNames        []string    // gen by `ExportFields`
	ExportFieldK8s          []string    // gen by `ExportFields`

	ExportFieldStructTags [MAX_DATASOURCE_ID][]StructTags // gen by `ExportFields` and init when exporting item first time
	TagFieltertStructTags [MAX_DATASOURCE_ID][]StructTags // gen by `TagFilters`  and init when exporting item first time

	// private configuration
	ExtraHeaders map[string]string `yaml:"extra-headers"`

	// kafka private configuration
	Sasl Sasl `yaml:"sasl"`
}

type Sasl struct {
	Enabled          bool   `yaml:"enabled"`
	SecurityProtocol string `yaml:"security-protocol"` // only support 'SASL_SSL'
	Mechanism        string `yaml:"sasl-mechanism"`    // only support 'PLAIN'
	Username         string `yaml:"username"`
	Password         string `yaml:"password"`
}

func (s *Sasl) Validate() error {
	if !s.Enabled {
		return nil
	}
	if s.SecurityProtocol != SecurityProtocol {
		log.Warningf("'sasl-protocol' only support value %s", SecurityProtocol)
	}
	if s.Mechanism != sarama.SASLTypePlaintext {
		log.Warningf("'sasl-mechanism' only support value %s", sarama.SASLTypePlaintext)
	}
	return nil
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
	PROTOCOL_PROMETHEUS: "prometheus",
	PROTOCOL_KAFKA:      "kafka",
	MAX_PROTOCOL_ID:     "unknown",
}

func stringToExportProtocol(str string) ExportProtocol {
	for i, v := range protocolToStrings {
		if v == str {
			return ExportProtocol(i)
		}
	}
	log.Warningf("unsupport export protocol: %s, support protocols %v", str, protocolToStrings[:MAX_PROTOCOL_ID])
	return MAX_PROTOCOL_ID
}

func (p ExportProtocol) String() string {
	return protocolToStrings[p]
}

func (cfg *ExporterCfg) Validate() error {
	l := len(cfg.Endpoints)
	cfg.RandomEndpoints = make([]string, 0, l)
	for _, v := range rand.Perm(l) {
		cfg.RandomEndpoints = append(cfg.RandomEndpoints, cfg.Endpoints[v])
	}

	if cfg.BatchSize == 0 {
		if cfg.Protocol == protocolToStrings[PROTOCOL_OTLP] {
			cfg.BatchSize = DefaultExportOtlpBatchSize
		} else {
			cfg.BatchSize = DefaultExportOtherBatchSize
		}
	}

	if cfg.QueueCount == 0 {
		cfg.QueueCount = DefaultExportQueueCount
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = DefaultExportQueueSize
	}
	if len(cfg.ExportFields) == 0 {
		cfg.ExportFields = DefaultExportCategory
	}
	cfg.DataSourceBits = StringsToDataSourceBits(cfg.DataSources)
	cfg.ExportFieldCategoryBits = StringsToCategoryBits(cfg.ExportFields)
	cfg.ExportFieldNames = cfg.ExportFields
	cfg.ExportProtocol = stringToExportProtocol(cfg.Protocol)
	cfg.ExportFieldK8s = GetK8sLabelConfigs(cfg.ExportFields)
	for i := range cfg.TagFilters {
		cfg.TagFilters[i].Validate()
	}
	cfg.Sasl.Validate()

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

	// tags
	FLOW_INFO uint64 = 1 << iota
	UNIVERSAL_TAG
	CUSTOM_TAG
	NATIVE_TAG
	NETWORK_LAYER
	TUNNEL_INFO
	TRANSPORT_LAYER
	APPLICATION_LAYER
	SERVICE_INFO
	TRACING_INFO
	CAPTURE_INFO
	EVENT_INFO // perf_event only
	DATA_LINK_LAYER

	// metrics
	L3_THROUGHPUT // network*/l4_flow_log
	L4_THROUGHPUT // network*/l4_flow_log
	TCP_SLOW      // network*/l4_flow_log
	TCP_ERROR     // network*/l4_flow_log
	APPLICATION   // network*/l4_flow_log
	THROUGHPUT    // application*/l7_flow_log
	ERROR         // application*/l7_flow_log
	DELAY         // all network/application/flow_log

	K8S_LABEL
	TAG     = FLOW_INFO | UNIVERSAL_TAG | CUSTOM_TAG | NATIVE_TAG | NETWORK_LAYER | TUNNEL_INFO | TRANSPORT_LAYER | APPLICATION_LAYER | SERVICE_INFO | TRACING_INFO | CAPTURE_INFO | DATA_LINK_LAYER
	METRICS = L3_THROUGHPUT | L4_THROUGHPUT | TCP_SLOW | TCP_ERROR | APPLICATION | THROUGHPUT | ERROR | DELAY
)

var categoryStringMap = map[string]uint64{
	CATEGORY_TAG:        TAG, // contains the sucategories before METRICS
	"flow_info":         FLOW_INFO,
	"universal_tag":     UNIVERSAL_TAG,
	"custom_tag":        CUSTOM_TAG,
	"native_tag":        NATIVE_TAG,
	"network_layer":     NETWORK_LAYER,
	"tunnel_info":       TUNNEL_INFO,
	"transport_layer":   TRANSPORT_LAYER,
	"application_layer": APPLICATION_LAYER,
	"service_info":      SERVICE_INFO,
	"tracing_info":      TRACING_INFO,
	"capture_info":      CAPTURE_INFO,
	"event_info":        EVENT_INFO,
	"data_link_layer":   DATA_LINK_LAYER,
	CATEGORY_K8S_LABEL:  K8S_LABEL,

	CATEGORY_METRICS: METRICS, // contains the following sucategories
	"l3_throughput":  L3_THROUGHPUT,
	"l4_throughput":  L4_THROUGHPUT,
	"tcp_slow":       TCP_SLOW,
	"tcp_error":      TCP_ERROR,
	"application":    APPLICATION,
	"throughput":     THROUGHPUT,
	"error":          ERROR,
	"delay":          DELAY,
}

func StringToCategoryBit(str string) uint64 {
	if str == "" {
		return UNKNOWN_CATEGORY
	}
	t, ok := categoryStringMap[str]
	if !ok {
		log.Warningf("unknown export category: %s", str)
	}
	return uint64(t)
}

func StringsToCategoryBits(strs []string) uint64 {
	ret := uint64(0)
	for _, str := range strs {
		if !strings.HasPrefix(str, "$") {
			continue
		}
		if str == CATEGORY_K8S_LABEL {
			ret |= categoryStringMap[str]
			continue
		}
		// format: 'category.subcategory'
		categorys := strings.Split(str, ".")
		category := categorys[0]
		// prioritize matching subcategory
		if len(categorys) > 1 && categorys[1] != "" {
			category = categorys[1]
		}
		t, ok := categoryStringMap[category]
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
	k8sPrefix := CATEGORY_K8S_LABEL + "."
	k8sPrefixLen := len(k8sPrefix)
	for _, str := range strs {
		// subfield
		if len(str) > k8sPrefixLen && strings.HasPrefix(str, k8sPrefix) {
			ret = append(ret, str[k8sPrefixLen:])
			// regexp field
		} else if len(str) > k8sPrefixLen+1 && strings.HasPrefix(str, "~"+k8sPrefix) {
			ret = append(ret, "~"+str[k8sPrefixLen+1:])
			// whole k8s.label category
		} else if str == k8sPrefix[:k8sPrefixLen-1] {
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
