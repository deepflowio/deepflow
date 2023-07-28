/*
 * Copyright (c) 2023 Yunshan Networks
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

package metrics

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	ckcommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("clickhouse.metrics")

const METRICS_OPERATOR_GTE = ">="
const METRICS_OPERATOR_LTE = "<="

var METRICS_OPERATORS = []string{METRICS_OPERATOR_GTE, METRICS_OPERATOR_LTE}

type Metrics struct {
	Index       int    // 索引
	DBField     string // 数据库字段
	DisplayName string // 描述
	Unit        string // 单位
	Type        int    // 指标量类型
	Category    string // 类别
	Condition   string // 聚合过滤
	IsAgg       bool   // 是否为聚合指标量
	Permissions []bool // 指标量的权限控制
	Table       string // 所属表
	Description string // 描述
}

func (m *Metrics) Replace(metrics *Metrics) {
	m.IsAgg = metrics.IsAgg
	if metrics.DBField != "" {
		m.DBField = metrics.DBField
	}
	if metrics.Condition != "" {
		m.Condition = metrics.Condition
	}
}

func (m *Metrics) SetIsAgg(isAgg bool) *Metrics {
	m.IsAgg = isAgg
	return m
}

func NewMetrics(
	index int, dbField string, displayname string, unit string, metricType int, category string,
	permissions []bool, condition string, table string, description string,
) *Metrics {
	return &Metrics{
		Index:       index,
		DBField:     dbField,
		DisplayName: displayname,
		Unit:        unit,
		Type:        metricType,
		Category:    category,
		Permissions: permissions,
		Condition:   condition,
		Table:       table,
		Description: description,
	}
}

func NewReplaceMetrics(dbField string, condition string) *Metrics {
	return &Metrics{
		DBField:   dbField,
		Condition: condition,
		IsAgg:     true,
	}
}

func GetAggMetrics(field string, db string, table string, ctx context.Context) (*Metrics, bool) {
	field = strings.Trim(field, "`")
	if field == COUNT_METRICS_NAME {
		return &Metrics{
			Index:       0,
			DBField:     COUNT_METRICS_NAME,
			DisplayName: COUNT_METRICS_NAME,
			Type:        METRICS_TYPE_OTHER,
			Category:    "Other",
			Permissions: []bool{true, true, true},
			Table:       table,
		}, true
	}
	return GetMetrics(field, db, table, ctx)
}

func GetMetrics(field string, db string, table string, ctx context.Context) (*Metrics, bool) {
	field = strings.Trim(field, "`")
	if db == "ext_metrics" || db == "deepflow_system" || table == "l7_flow_log" {
		fieldSplit := strings.Split(field, ".")
		if len(fieldSplit) > 1 {
			if fieldSplit[0] == "metrics" {
				fieldName := strings.Replace(field, "metrics.", "", 1)
				metrics_names_field, metrics_values_field := METRICS_ARRAY_NAME_MAP[db][0], METRICS_ARRAY_NAME_MAP[db][1]
				return NewMetrics(
					0, fmt.Sprintf("if(indexOf(%s, '%s')=0,null,%s[indexOf(%s, '%s')])", metrics_names_field, fieldName, metrics_values_field, metrics_names_field, fieldName),
					field, "", METRICS_TYPE_COUNTER,
					"metrics", []bool{true, true, true}, "", table, "",
				), true
			}
		}
	} else if db == ckcommon.DB_NAME_PROMETHEUS {
		return NewMetrics(
			0, field,
			field, "", METRICS_TYPE_COUNTER,
			"metrics", []bool{true, true, true}, "", table, "",
		), true
	}
	allMetrics, err := GetMetricsByDBTableStatic(db, table, "")
	if err != nil {
		return nil, false
	}
	metric, ok := allMetrics[field]
	return metric, ok
}

func GetMetricsByDBTableStatic(db string, table string, where string) (map[string]*Metrics, error) {
	var err error
	switch db {
	case "flow_log":
		switch table {
		case "l4_flow_log":
			return GetL4FlowLogMetrics(), err
		case "l4_packet":
			return GetL4PacketMetrics(), err
		case "l7_flow_log":
			return GetL7FlowLogMetrics(), err
		case "l7_packet":
			return GetL7PacketMetrics(), err
		}
	case "flow_metrics":
		switch table {
		case "vtap_flow_port":
			return GetVtapFlowPortMetrics(), err
		case "vtap_flow_edge_port":
			return GetVtapFlowEdgePortMetrics(), err
		case "vtap_app_port":
			return GetVtapAppPortMetrics(), err
		case "vtap_app_edge_port":
			return GetVtapAppEdgePortMetrics(), err
		case "vtap_acl":
			return GetVtapAclMetrics(), err
		}
	case "event":
		switch table {
		case "event":
			return GetResourceEventMetrics(), err
		case "perf_event":
			return GetResourcePerfEventMetrics(), err
		case "alarm_event":
			return GetAlarmEventMetrics(), err
		}
	case ckcommon.DB_NAME_PROFILE:
		switch table {
		case "in_process":
			return GetInProcessMetrics(), err
		}
	}
	return nil, err
}

func GetMetricsByDBTable(db string, table string, where string, ctx context.Context) (map[string]*Metrics, error) {
	var err error
	switch db {
	case "flow_log":
		switch table {
		case "l4_flow_log":
			return GetL4FlowLogMetrics(), err
		case "l4_packet":
			return GetL4PacketMetrics(), err
		case "l7_packet":
			return GetL7PacketMetrics(), err
		case "l7_flow_log":
			metrics := make(map[string]*Metrics)
			loads := GetL7FlowLogMetrics()
			exts, err := GetExtMetrics(db, table, where, ctx)
			for k, v := range loads {
				if _, ok := metrics[k]; !ok {
					metrics[k] = v
				}
			}
			loadsLen := len(loads)
			for k, v := range exts {
				if _, ok := metrics[k]; !ok {
					v.Index += loadsLen
					metrics[k] = v
				}
			}
			metrics["metrics"] = NewMetrics(
				len(metrics), "metrics",
				"metrics", "", METRICS_TYPE_ARRAY,
				"metrics", []bool{true, true, true}, "", table, "",
			)
			return metrics, err
		}
	case "flow_metrics":
		switch table {
		case "vtap_flow_port":
			return GetVtapFlowPortMetrics(), err
		case "vtap_flow_edge_port":
			return GetVtapFlowEdgePortMetrics(), err
		case "vtap_app_port":
			return GetVtapAppPortMetrics(), err
		case "vtap_app_edge_port":
			return GetVtapAppEdgePortMetrics(), err
		case "vtap_acl":
			return GetVtapAclMetrics(), err
		}
	case "event":
		switch table {
		case "event":
			return GetResourceEventMetrics(), err
		case "perf_event":
			return GetResourcePerfEventMetrics(), err
		case "alarm_event":
			return GetAlarmEventMetrics(), err
		}
	case ckcommon.DB_NAME_PROFILE:
		switch table {
		case "in_process":
			return GetInProcessMetrics(), err
		}
	case "ext_metrics", "deepflow_system":
		return GetExtMetrics(db, table, where, ctx)
	case ckcommon.DB_NAME_PROMETHEUS:
		return GetPrometheusMetrics(db, table, where, ctx)
	}

	return nil, err
}

func GetMetricsDescriptionsByDBTable(db string, table string, where string, ctx context.Context) ([]interface{}, error) {
	allMetrics, err := GetMetricsByDBTable(db, table, where, ctx)
	if allMetrics == nil || err != nil {
		// TODO: metrics not found
		return nil, err
	}
	/* columns := []interface{}{
		"name", "is_agg", "display_name", "unit", "type", "category", "operators", "permissions", "table"
	} */
	values := make([]interface{}, len(allMetrics))
	for field, metrics := range allMetrics {
		if db == "ext_metrics" || db == "deepflow_system" || (table == "l7_flow_log" && strings.Contains(field, "metrics.")) {
			field = metrics.DisplayName
		} else if db == ckcommon.DB_NAME_PROMETHEUS {
			index := strings.LastIndex(field, "-")
			if index != -1 {
				field = field[:index]
			}
		}
		values[metrics.Index] = []interface{}{
			field, metrics.IsAgg, metrics.DisplayName, metrics.Unit, metrics.Type,
			metrics.Category, METRICS_OPERATORS, metrics.Permissions, metrics.Table,
			metrics.Description,
		}
	}
	return values, nil
}

func GetMetricsDescriptions(db string, table string, where string, ctx context.Context) (*common.Result, error) {
	var values []interface{}
	if table == "" && db != ckcommon.DB_NAME_PROMETHEUS {
		var tables []interface{}
		if db == "ext_metrics" {
			tables = append(tables, table)
		} else if db == "deepflow_system" {
			for _, extTables := range ckcommon.GetExtTables(db, ctx) {
				for i, extTable := range extTables.([]interface{}) {
					if i == 0 {
						tables = append(tables, extTable)
					}
				}
			}
		} else {
			for _, dbTable := range ckcommon.DB_TABLE_MAP[db] {
				tables = append(tables, dbTable)
			}
		}
		for _, dbTable := range tables {
			metrics, err := GetMetricsDescriptionsByDBTable(db, dbTable.(string), where, ctx)
			if err != nil {
				return nil, err
			}
			values = append(values, metrics...)
		}
	} else {
		metrics, err := GetMetricsDescriptionsByDBTable(db, table, where, ctx)
		if err != nil {
			return nil, err
		}
		values = append(values, metrics...)
	}
	columns := []interface{}{
		"name", "is_agg", "display_name", "unit", "type", "category", "operators", "permissions", "table", "description",
	}
	return &common.Result{
		Columns: columns,
		Values:  values,
	}, nil
}

func LoadMetrics(db string, table string, dbDescription map[string]interface{}) (loadMetrics map[string]*Metrics, err error) {
	tableDate, ok := dbDescription[db]
	if !ok {
		return nil, errors.New(fmt.Sprintf("get metrics failed! db: %s", db))
	}

	if ok {
		metricsData, ok := tableDate.(map[string]interface{})[table]
		metricsDataLanguage, _ := tableDate.(map[string]interface{})[table+"."+config.Cfg.Language]
		if ok {
			loadMetrics = make(map[string]*Metrics)
			for i, metrics := range metricsData.([][]interface{}) {
				if len(metrics) < 5 {
					return nil, errors.New(fmt.Sprintf("get metrics failed! db:%s table:%s metrics:%v", db, table, metrics))
				}
				metricType, ok := METRICS_TYPE_NAME_MAP[metrics[2].(string)]
				if !ok {
					return nil, errors.New(fmt.Sprintf("get metrics type failed! db:%s table:%s metrics:%v", db, table, metrics))
				}
				permissions, err := ckcommon.ParsePermission(metrics[4])
				if err != nil {
					return nil, errors.New(fmt.Sprintf("parse metrics permission failed! db:%s table:%s metrics:%v", db, table, metrics))
				}
				metricsLanguage := metricsDataLanguage.([][]interface{})[i]
				displayName := metricsLanguage[1].(string)
				unit := metricsLanguage[2].(string)
				description := metricsLanguage[3].(string)
				lm := NewMetrics(
					i, metrics[1].(string), displayName, unit, metricType,
					metrics[3].(string), permissions, "", table, description,
				)
				loadMetrics[metrics[0].(string)] = lm
			}

		} else {
			return nil, errors.New(fmt.Sprintf("get metrics failed! db:%s table:%s", db, table))
		}
	}
	return loadMetrics, nil
}

func MergeMetrics(db string, table string, loadMetrics map[string]*Metrics) error {
	var metrics map[string]*Metrics
	var replaceMetrics map[string]*Metrics
	switch db {
	case "flow_log":
		switch table {
		case "l4_flow_log":
			metrics = L4_FLOW_LOG_METRICS
			replaceMetrics = L4_FLOW_LOG_METRICS_REPLACE
		case "l4_packet":
			metrics = L4_PACKET_METRICS
			replaceMetrics = L4_PACKET_METRICS_REPLACE
		case "l7_packet":
			metrics = L7_PACKET_METRICS
			replaceMetrics = L7_PACKET_METRICS_REPLACE
		case "l7_flow_log":
			metrics = L7_FLOW_LOG_METRICS
			replaceMetrics = L7_FLOW_LOG_METRICS_REPLACE
		}
	case "flow_metrics":
		switch table {
		case "vtap_flow_port":
			metrics = VTAP_FLOW_PORT_METRICS
			replaceMetrics = VTAP_FLOW_PORT_METRICS_REPLACE
		case "vtap_flow_edge_port":
			metrics = VTAP_FLOW_EDGE_PORT_METRICS
			replaceMetrics = VTAP_FLOW_EDGE_PORT_METRICS_REPLACE
		case "vtap_app_port":
			metrics = VTAP_APP_PORT_METRICS
			replaceMetrics = VTAP_APP_PORT_METRICS_REPLACE
		case "vtap_app_edge_port":
			metrics = VTAP_APP_EDGE_PORT_METRICS
			replaceMetrics = VTAP_APP_EDGE_PORT_METRICS_REPLACE
		case "vtap_acl":
			metrics = VTAP_ACL_METRICS
			replaceMetrics = VTAP_ACL_METRICS_REPLACE
		}
	case "event":
		switch table {
		case "event":
			metrics = RESOURCE_EVENT_METRICS
			replaceMetrics = RESOURCE_EVENT_METRICS_REPLACE
		case "perf_event":
			metrics = RESOURCE_PERF_EVENT_METRICS
			replaceMetrics = RESOURCE_PERF_EVENT_METRICS_REPLACE
		case "alarm_event":
			metrics = ALARM_EVENT_METRICS
			replaceMetrics = ALARM_EVENT_METRICS_REPLACE
		}
	case ckcommon.DB_NAME_PROFILE:
		switch table {
		case "in_process":
			metrics = IN_PROCESS_METRICS
			replaceMetrics = IN_PROCESS_METRICS_REPLACE
		}
	case ckcommon.DB_NAME_PROMETHEUS:
		metrics = PROMETHEUS_METRICS
		replaceMetrics = PROMETHEUS_METRICS_REPLACE

	case "ext_metrics", "deepflow_system":
		metrics = EXT_METRICS
	}
	if metrics == nil {
		return errors.New(fmt.Sprintf("merge metrics failed! db:%s, table:%s", db, table))
	}
	for name, value := range loadMetrics {
		// TAG类型指标量都属于聚合类型
		if value.Type == METRICS_TYPE_TAG {
			value.IsAgg = true
		}
		if rm, ok := replaceMetrics[name]; ok && value.DBField == "" {
			value.Replace(rm)
		}
		if name == COUNT_METRICS_NAME {
			value.IsAgg = true
		}
		metrics[name] = value
	}
	return nil
}
