/*
 * Copyright (c) 2022 Yunshan Networks
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

package reciter_api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	DefaultQueryTimeout    = 2 * time.Minute
	DefaultInfluxDBTimeout = time.Minute
	DefaultExchangeTimeout = 10 * time.Second
)

func init() {
	AggOpMapRev = make(map[AggOp]string)
	for k, v := range AggOpMap {
		AggOpMapRev[v] = k
	}
	PeriAggOpMapRev = make(map[PeriAggOp]string)
	for k, v := range PeriAggOpMap {
		PeriAggOpMapRev[v] = k
	}
}

type Query struct {
	SQL string `json:"sql"`

	IPMaskLen  int `json:"ip_mask_len"`
	IPMaskLen0 int `json:"ip_mask_len_0"`
	IPMaskLen1 int `json:"ip_mask_len_1"`

	GroupIDMap []GroupIDMap `json:"group_id_map"`
	TagIDMap   []TagIDMap   `json:"tag_id_map"`

	NewTagFilters []NewTagFilter `json:"new_tag_filters"`

	CustomTagMap []KeyValuePair `json:"custom_tag_map"`

	GroupByTags []AdaptiveGroupBy `json:"group_by_tags"`
}

type QueryData struct {
	QueryID        uint32   `json:"query_id"`
	DBPort         uint16   `json:"db_port"`
	Reciters       []string `json:"reciters"`
	ThisReciter    int      `json:"this_reciter"`
	ReduceReciters []string `json:"reduce_reciters"`

	/* 老查询结构体, 逐步废弃 */
	SQL string `json:"sql"`

	IPMaskLen  int `json:"ip_mask_len"`
	IPMaskLen0 int `json:"ip_mask_len_0"`
	IPMaskLen1 int `json:"ip_mask_len_1"`

	GroupIDMap []GroupIDMap `json:"group_id_map"`
	TagIDMap   []TagIDMap   `json:"tag_id_map"`

	NewTagFilters []NewTagFilter `json:"new_tag_filters"`

	CustomTagMap []KeyValuePair `json:"custom_tag_map"`

	GroupByTags         []TagName         `json:"group_by_tags"`
	AdaptiveGroupByTags []AdaptiveGroupBy `json:"adaptive_group_by_tags"`
	/* 老查询结构体 */

	/* 新查询结构体 */
	Queries []Query `json:"queries"`

	GroupByTime `json:"group_by_time"`
	// 时间单位，默认值ms，毫秒
	TimeUnit `json:"time_unit"`

	PreAggregation  []PeriAggregation `json:"pre_aggs"`
	Aggregation     []Aggregation     `json:"aggs"`
	PostAggregation []PeriAggregation `json:"post_aggs"`

	Sort       `json:"sort"`
	MeterRange `json:"meter_range"`

	QueryTimeout    Duration `json:"query_timeout"`
	InfluxDBTimeout Duration `json:"influx_db_timeout"`
	ExchangeTimeout Duration `json:"exchange_timeout"`

	SpanContext string `json:"span_context"`
}

type Duration time.Duration

func (d Duration) String() string {
	return time.Duration(d).String()
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%s", time.Duration(d)))
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(tmp)
		return nil
	default:
		return errors.New("invalid duration")
	}
}

const (
	GROUP_ID_MAP_ROLE_CLIENT = "client"
	GROUP_ID_MAP_ROLE_SERVER = "server"
	GROUP_ID_MAP_ROLE_BOTH   = "both"
)

type GroupIDMap struct {
	L3EpcID     int32    `json:"l3_epc_id"`
	GroupID     uint16   `json:"group_id"`
	CIDRs       []string `json:"cidrs"`
	IPRanges    []string `json:"ip_ranges"` // 格式为{IP0}-{IP1}, 如 10.33.2.202-10.34.1.233
	PodGroupID  uint16   `json:"pod_group_id"`
	Protocol    uint16   `json:"protocol"`     // 协议用256表示任意，所以长度至少为9bit
	ServerPorts string   `json:"server_ports"` // 格式为逗号分隔的IP范围，如 22,12000-13000
	Role        string   `json:"role"`
	ServiceID   uint32   `json:"service_id"`
}

type TagIDMap struct {
	Fields          []TagName         `json:"fields"`
	ResultFieldName string            `json:"result_field_name"`
	RawRules        []TagIDMapRawRule `json:"rules"`   // 该字段只用于JSON序列化和反序列化
	RawDefault      string            `json:"default"` // 同上
	Rules           []TagIDMapRule    `json:"-"`
	Default         int32             `json:"-"`
}

var SUPPORTED_ID_MAP = []struct {
	Fields          []TagName
	ResultFieldName string
}{
	{
		Fields:          []TagName{TAG_L3_EPC_ID_1},
		ResultFieldName: string(TAG_L3_EPC_ID_1),
	},
	{
		Fields:          []TagName{TAG_GROUP_ID},
		ResultFieldName: "business_id",
	},
	{
		Fields:          []TagName{TAG_GROUP_ID_0},
		ResultFieldName: "business_id_0",
	},
	{
		Fields:          []TagName{TAG_GROUP_ID_1},
		ResultFieldName: "business_id_1",
	},
}

type TagIDMapRawRule struct {
	From [][]string `json:"from"`
	To   string     `json:"to"`
}

type TagIDMapRule struct {
	From [][]int32
	To   int32
}

func (m *TagIDMap) ParseRawRules() error {
	defaultValue, err := strconv.ParseInt(m.RawDefault, 10, 32)
	if err != nil {
		return err
	}
	m.Default = int32(defaultValue)
	parser := func(id string) (int32, error) {
		v, err := strconv.ParseInt(id, 10, 32)
		return int32(v), err
	}
	for _, rawRule := range m.RawRules {
		ruleTo, err := strconv.ParseInt(rawRule.To, 10, 32)
		if err != nil {
			return err
		}
		rule := TagIDMapRule{
			From: make([][]int32, len(rawRule.From)),
			To:   int32(ruleTo),
		}
		for i, fromIDs := range rawRule.From {
			rule.From[i] = make([]int32, len(fromIDs))
			for j, fromID := range fromIDs {
				var err error
				if rule.From[i][j], err = parser(fromID); err != nil {
					return err
				}
			}
		}
		m.Rules = append(m.Rules, rule)
	}
	return nil
}

type KeyValuePair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type TagName string

const (
	TAG_IP             TagName = "ip"
	TAG_GROUP_ID       TagName = "group_id"
	TAG_L2_EPC_ID      TagName = "l2_epc_id"
	TAG_L3_EPC_ID      TagName = "l3_epc_id"
	TAG_L2_DEVICE_ID   TagName = "l2_device_id"
	TAG_L2_DEVICE_TYPE TagName = "l2_device_type"
	TAG_L3_DEVICE_ID   TagName = "l3_device_id"
	TAG_L3_DEVICE_TYPE TagName = "l3_device_type"
	TAG_HOST_ID        TagName = "host_id"
	TAG_SUBNET_ID      TagName = "subnet_id"
	TAG_REGION_ID      TagName = "region_id"
	TAG_POD_ID         TagName = "pod_id"
	TAG_POD_NODE_ID    TagName = "pod_node_id"
	TAG_POD_NS_ID      TagName = "pod_ns_id"
	TAG_POD_GROUP_ID   TagName = "pod_group_id"
	TAG_POD_CLUSTER_ID TagName = "pod_cluster_id"
	TAG_AZ_ID          TagName = "az_id"
)

const (
	TAG_IP_0             TagName = "ip_0"
	TAG_IP_1             TagName = "ip_1"
	TAG_GROUP_ID_0       TagName = "group_id_0"
	TAG_GROUP_ID_1       TagName = "group_id_1"
	TAG_L2_EPC_ID_0      TagName = "l2_epc_id_0"
	TAG_L2_EPC_ID_1      TagName = "l2_epc_id_1"
	TAG_L3_EPC_ID_0      TagName = "l3_epc_id_0"
	TAG_L3_EPC_ID_1      TagName = "l3_epc_id_1"
	TAG_L2_DEVICE_ID_0   TagName = "l2_device_id_0"
	TAG_L2_DEVICE_ID_1   TagName = "l2_device_id_1"
	TAG_L2_DEVICE_TYPE_0 TagName = "l2_device_type_0"
	TAG_L2_DEVICE_TYPE_1 TagName = "l2_device_type_1"
	TAG_L3_DEVICE_ID_0   TagName = "l3_device_id_0"
	TAG_L3_DEVICE_ID_1   TagName = "l3_device_id_1"
	TAG_L3_DEVICE_TYPE_0 TagName = "l3_device_type_0"
	TAG_L3_DEVICE_TYPE_1 TagName = "l3_device_type_1"
	TAG_HOST_ID_0        TagName = "host_id_0"
	TAG_HOST_ID_1        TagName = "host_id_1"
	TAG_SUBNET_ID_0      TagName = "subnet_id_0"
	TAG_SUBNET_ID_1      TagName = "subnet_id_1"
	TAG_REGION_ID_0      TagName = "region_id_0"
	TAG_REGION_ID_1      TagName = "region_id_1"
	TAG_POD_ID_0         TagName = "pod_id_0"
	TAG_POD_ID_1         TagName = "pod_id_1"
	TAG_POD_NODE_ID_0    TagName = "pod_node_id_0"
	TAG_POD_NODE_ID_1    TagName = "pod_node_id_1"
	TAG_POD_NS_ID_0      TagName = "pod_ns_id_0"
	TAG_POD_NS_ID_1      TagName = "pod_ns_id_1"
	TAG_POD_GROUP_ID_0   TagName = "pod_group_id_0"
	TAG_POD_GROUP_ID_1   TagName = "pod_group_id_1"
	TAG_POD_CLUSTER_ID_0 TagName = "pod_cluster_id_0"
	TAG_POD_CLUSTER_ID_1 TagName = "pod_cluster_id_1"
	TAG_AZ_ID_0          TagName = "az_id_0"
	TAG_AZ_ID_1          TagName = "az_id_1"
)

const (
	TAG_DIRECTION   TagName = "direction"
	TAG_TAP_SIDE    TagName = "tap_side"
	TAG_ACL_GID     TagName = "acl_gid"
	TAG_PROTOCOL    TagName = "protocol"
	TAG_SERVER_PORT TagName = "server_port"
	TAG_TAP_PORT    TagName = "tap_port"
	TAG_TAP_TYPE    TagName = "tap_type"
	TAG_TAG_TYPE    TagName = "tag_type"
	TAG_TAG_VALUE   TagName = "tag_value"
	TAG_VTAP_ID     TagName = "vtap_id"
)

const (
	// 以下tag仅用于输出附带
	TAG_TIMESTAMP  TagName = "time"
	TAG_IP_VERSION TagName = "ip_version"
)

var TagCodeMap = map[TagName]struct{}{
	// 把ip_version tag并入code IP进行处理
	// 如果聚合tag中有TAG_IP_VERSION而没有TAG_IP，需要将IP字段清空以保证聚合出一个结果
	TAG_IP_VERSION: {},

	TAG_IP:               {},
	TAG_GROUP_ID:         {},
	TAG_L3_EPC_ID:        {},
	TAG_L3_DEVICE_ID:     {},
	TAG_L3_DEVICE_TYPE:   {},
	TAG_HOST_ID:          {},
	TAG_SUBNET_ID:        {},
	TAG_REGION_ID:        {},
	TAG_POD_ID:           {},
	TAG_POD_NODE_ID:      {},
	TAG_POD_NS_ID:        {},
	TAG_POD_GROUP_ID:     {},
	TAG_POD_CLUSTER_ID:   {},
	TAG_AZ_ID:            {},
	TAG_IP_0:             {},
	TAG_IP_1:             {},
	TAG_GROUP_ID_0:       {},
	TAG_GROUP_ID_1:       {},
	TAG_L3_EPC_ID_0:      {},
	TAG_L3_EPC_ID_1:      {},
	TAG_L3_DEVICE_ID_0:   {},
	TAG_L3_DEVICE_ID_1:   {},
	TAG_L3_DEVICE_TYPE_0: {},
	TAG_L3_DEVICE_TYPE_1: {},
	TAG_HOST_ID_0:        {},
	TAG_HOST_ID_1:        {},
	TAG_SUBNET_ID_0:      {},
	TAG_SUBNET_ID_1:      {},
	TAG_REGION_ID_0:      {},
	TAG_REGION_ID_1:      {},
	TAG_POD_ID_0:         {},
	TAG_POD_ID_1:         {},
	TAG_POD_NODE_ID_0:    {},
	TAG_POD_NODE_ID_1:    {},
	TAG_POD_NS_ID_0:      {},
	TAG_POD_NS_ID_1:      {},
	TAG_POD_GROUP_ID_0:   {},
	TAG_POD_GROUP_ID_1:   {},
	TAG_POD_CLUSTER_ID_0: {},
	TAG_POD_CLUSTER_ID_1: {},
	TAG_AZ_ID_0:          {},
	TAG_AZ_ID_1:          {},
	TAG_DIRECTION:        {},
	TAG_TAP_SIDE:         {},
	TAG_ACL_GID:          {},
	TAG_PROTOCOL:         {},
	TAG_SERVER_PORT:      {},
	TAG_TAP_PORT:         {},
	TAG_TAP_TYPE:         {},
	TAG_TAG_TYPE:         {},
	TAG_TAG_VALUE:        {},
	TAG_VTAP_ID:          {},
}

// NewTagFilter支持group_id/group_id_0/group_id_1的过滤
// 同样的tag只支持查询一个
// In/NotIn/ExcludeSet的优先级从上到下
type NewTagFilter struct {
	TagName    `json:"tag_name"`
	In         []int32 `json:"in"`
	NotIn      []int32 `json:"not_in"`
	ExcludeSet []int32 `json:"exclude_set"`
}

type GroupByTime struct {
	Step        Duration `json:"step"`
	WindowSize  Duration `json:"window_size"`
	Offset      Duration `json:"offset"`
	Granularity Duration `json:"granularity"`

	// 请求里不填写的字段
	StepInSeconds        int32 `json:"-"`
	WindowSizeInSeconds  int32 `json:"-"`
	OffsetInSeconds      int32 `json:"-"`
	GranularityInSeconds int32 `json:"-"`
}

func (t *GroupByTime) AlignTimestamp(ts uint32) uint32 {
	if t.WindowSizeInSeconds == 0 {
		return 0
	}
	return uint32((int32(ts)+t.OffsetInSeconds)/t.StepInSeconds*t.StepInSeconds - t.OffsetInSeconds)
}

func (t *GroupByTime) GetEffectiveTimestampRange(ts uint32) (uint32, uint32) {
	if t.Step == t.WindowSize {
		aligned := t.AlignTimestamp(ts)
		return aligned, aligned
	}
	aligned := t.AlignTimestamp(ts + uint32(t.StepInSeconds) - 1)
	return aligned, aligned + uint32(t.WindowSizeInSeconds) - uint32(t.StepInSeconds)
}

type TimeUnit string

const (
	TIME_UNIT_SECOND      TimeUnit = "s"
	TIME_UNIT_MILLISECOND TimeUnit = "ms"
)

type AdaptiveGroupBy struct {
	Tags       []TagName   `json:"tags"`
	AlterTags  []TagName   `json:"alter_tags"`
	TieredTags [][]TagName `json:"tiered_tags"`
}

type AggOp uint8

const (
	AGG_OP_SUM AggOp = iota
	AGG_OP_MAX
	AGG_OP_MIN
	AGG_OP_AVG
	AGG_OP_AVG_SUM
	AGG_OP_LAST_SUM
	AGG_OP_MAX_SUM
	AGG_OP_MIN_SUM
	AGG_OP_MAX_DIV_SUM
	AGG_OP_MIN_DIV_SUM
	AGG_OP_DISTINCT
	AGG_OP_PERCENTILE
	AGG_OP_PERCENTILE_SUM
	AGG_OP_PERCENTILE_DIV_SUM
	AGG_OP_AVG_DIV_SUM
	AGG_OP_STDDEV
	AGG_OP_STDDEV_SUM
	AGG_OP_STDDEV_DIV_SUM
	AGG_OP_HISTOGRAM
	AGG_OP_HISTOGRAM_SUM
	AGG_OP_HISTOGRAM_DIV_SUM
)

var AggOpMap = map[string]AggOp{
	"sum_sum":            AGG_OP_SUM,
	"max_max":            AGG_OP_MAX,
	"min_min":            AGG_OP_MIN,
	"avg_avg":            AGG_OP_AVG,
	"avg_sum":            AGG_OP_AVG_SUM,
	"last_sum":           AGG_OP_LAST_SUM,
	"max_sum":            AGG_OP_MAX_SUM,
	"min_sum":            AGG_OP_MIN_SUM,
	"max_div_sum":        AGG_OP_MAX_DIV_SUM,
	"min_div_sum":        AGG_OP_MIN_DIV_SUM,
	"distinct":           AGG_OP_DISTINCT,
	"percentile":         AGG_OP_PERCENTILE,
	"percentile_sum":     AGG_OP_PERCENTILE_SUM,
	"percentile_div_sum": AGG_OP_PERCENTILE_DIV_SUM,
	"avg_div_sum":        AGG_OP_AVG_DIV_SUM,
	"stddev":             AGG_OP_STDDEV,
	"stddev_sum":         AGG_OP_STDDEV_SUM,
	"stddev_div_sum":     AGG_OP_STDDEV_DIV_SUM,
	"histogram":          AGG_OP_HISTOGRAM,
	"histogram_sum":      AGG_OP_HISTOGRAM_SUM,
	"histogram_div_sum":  AGG_OP_HISTOGRAM_DIV_SUM,
}

var AggOpMapRev map[AggOp]string

func (o AggOp) String() string {
	return AggOpMapRev[o]
}

func (o AggOp) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

func (o *AggOp) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case string:
		if op, in := AggOpMap[value]; in {
			*o = op
			return nil
		} else {
			return fmt.Errorf("invalid AggOp %s", value)
		}
	default:
		return errors.New("invalid AggOp")
	}
}

type Aggregation struct {
	Op              AggOp      `json:"op"`
	Parameters      []string   `json:"parameters"`
	DistinctExclude [][]string `json:"distinct_exclude"`
	Field           string     `json:"field"`
	Fields          []string   `json:"fields"`
	IsTimeField     bool       `json:"is_time_field"`
	ResultFieldName string     `json:"result_field_name"`
}

func (a *Aggregation) Validate() error {
	switch a.Op {
	case AGG_OP_DISTINCT:
		distinctLen := len(a.Parameters)
		for _, entry := range a.DistinctExclude {
			if len(entry) != distinctLen {
				return errors.New("distinct_exclude entry length mismatch with parameters")
			}
		}
	}
	return nil
}

// "peri-" means "around" / "about"
type PeriAggOp uint8

const (
	PERI_AGG_OP_SUM PeriAggOp = iota
	PERI_AGG_OP_DIV
	// Fields长度应为3，算法是f[0] + f[1] - f[2]
	PERI_AGG_OP_DEDUP_ADD
	PERI_AGG_OP_SUB
	PERI_AGG_OP_RELATIVE_SUB
)

var PeriAggFieldSize = map[PeriAggOp]int{
	PERI_AGG_OP_SUM:          2,
	PERI_AGG_OP_DIV:          2,
	PERI_AGG_OP_DEDUP_ADD:    3,
	PERI_AGG_OP_SUB:          2,
	PERI_AGG_OP_RELATIVE_SUB: 3,
}

var PeriAggOpMap = map[string]PeriAggOp{
	"sum":          PERI_AGG_OP_SUM,
	"div":          PERI_AGG_OP_DIV,
	"dedup_add":    PERI_AGG_OP_DEDUP_ADD,
	"sub":          PERI_AGG_OP_SUB,
	"relative_sub": PERI_AGG_OP_RELATIVE_SUB,
}

var PeriAggOpMapRev map[PeriAggOp]string

func (o PeriAggOp) String() string {
	return PeriAggOpMapRev[o]
}

func (o PeriAggOp) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

func (o *PeriAggOp) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case string:
		if op, in := PeriAggOpMap[value]; in {
			*o = op
			return nil
		} else {
			return fmt.Errorf("invalid PeriAggOp %s", value)
		}
	default:
		return errors.New("invalid PeriAggOp")
	}
}

type PeriAggregation struct {
	Op              PeriAggOp `json:"op"`
	Fields          []string  `json:"fields"`
	ResultFieldName string    `json:"result_field_name"`
}

type SortOrder string

const (
	SORT_ORDER_ASC  SortOrder = "asc"
	SORT_ORDER_DESC           = "desc"
)

type Sort struct {
	Field string    `json:"field"`
	Limit uint      `json:"limit"`
	Order SortOrder `json:"order"`
}

type MeterRange struct {
	Field string `json:"field"`
	Min   uint64 `json:"min"`
	Max   uint64 `json:"max"`
}

func (q *QueryData) FromBytes(b []byte) error {
	return json.Unmarshal(b, q)
}

func (q *QueryData) ToBytes() ([]byte, error) {
	result := bytes.NewBuffer([]byte{})
	jsonEncoder := json.NewEncoder(result)
	jsonEncoder.SetEscapeHTML(false)
	err := jsonEncoder.Encode(q)
	return []byte(result.String()), err
}
