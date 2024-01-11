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
	"regexp"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	ckcommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/trans_prometheus"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("clickhouse.metrics")

const METRICS_OPERATOR_GTE = ">="
const METRICS_OPERATOR_LTE = "<="

var METRICS_OPERATORS = []string{METRICS_OPERATOR_GTE, METRICS_OPERATOR_LTE}
var DB_DESCRIPTIONS map[string]interface{}
var letterRegexp = regexp.MustCompile("^[a-zA-Z]")

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
	newAllMetrics := map[string]*Metrics{}
	field = strings.Trim(field, "`")
	if db == "ext_metrics" || db == "deepflow_system" || table == "l7_flow_log" {
		fieldSplit := strings.Split(field, ".")
		if len(fieldSplit) > 1 {
			if fieldSplit[0] == "metrics" {
				fieldName := strings.Replace(field, "metrics.", "", 1)
				metrics_names_field, metrics_values_field := METRICS_ARRAY_NAME_MAP[db][0], METRICS_ARRAY_NAME_MAP[db][1]
				metric := NewMetrics(
					0, fmt.Sprintf("if(indexOf(%s, '%s')=0,null,%s[indexOf(%s, '%s')])", metrics_names_field, fieldName, metrics_values_field, metrics_names_field, fieldName),
					field, "", METRICS_TYPE_COUNTER,
					"metrics", []bool{true, true, true}, "", table, "",
				)
				newAllMetrics[field] = metric
			}
		}
	} else if db == ckcommon.DB_NAME_PROMETHEUS {
		metric := NewMetrics(
			0, field,
			field, "", METRICS_TYPE_COUNTER,
			"metrics", []bool{true, true, true}, "", table, "",
		)
		newAllMetrics[field] = metric
	}
	allMetrics, err := GetMetricsByDBTableStatic(db, table, "")
	if err != nil {
		return nil, false
	}
	// deep copy map
	for k, v := range allMetrics {
		newAllMetrics[k] = v
	}
	if err != nil {
		return nil, false
	}

	// tag metrics
	dbData, ok := DB_DESCRIPTIONS["clickhouse"]
	if !ok {
		return nil, false
	}
	dbDataMap := dbData.(map[string]interface{})
	if tagData, ok := dbDataMap["tag"]; ok {
		dbTagMap := tagData.(map[string]interface{})
		if dbTag, ok := dbTagMap[db]; ok {
			tableTagMap := dbTag.(map[string]interface{})
			newTable := table
			if db == ckcommon.DB_NAME_PROMETHEUS {
				newTable = "samples"
			} else if db == ckcommon.DB_NAME_EXT_METRICS {
				newTable = "ext_common"
			} else if db == ckcommon.DB_NAME_DEEPFLOW_SYSTEM {
				newTable = "deepflow_system_common"
			}
			if tableTag, ok := tableTagMap[newTable]; ok {
				tabletagSlice := tableTag.([][]interface{})
				for i, tagSlice := range tabletagSlice {
					tagType := tagSlice[3].(string)
					if slices.Contains([]string{"auto_custom_tag", "time", "id"}, tagType) {
						continue
					}
					if db == ckcommon.DB_NAME_FLOW_TAG {
						continue
					}
					name := tagSlice[0].(string)
					clientName := tagSlice[1].(string)
					serverName := tagSlice[2].(string)
					tagLanguage := tableTagMap[newTable+"."+config.Cfg.Language].([][]interface{})[i]
					displayName := tagLanguage[1].(string)
					permissions, err := ckcommon.ParsePermission("111")
					if err != nil {
						return nil, false
					}
					nameDBField, err := GetTagDBField(name, db, table)
					if err != nil {
						return nil, false
					}
					clientNameDBField, err := GetTagDBField(clientName, db, table)
					if err != nil {
						return nil, false
					}
					serverNameDBField, err := GetTagDBField(serverName, db, table)
					if err != nil {
						return nil, false
					}
					if slices.Contains([]string{"l4_flow_log", "l7_flow_log"}, table) || strings.Contains(table, "edge") {
						if serverName == clientName {
							clientNameMetric := NewMetrics(
								0, clientNameDBField, displayName, "", METRICS_TYPE_NAME_MAP["tag"],
								"Tag", permissions, "", table, "",
							)
							newAllMetrics[clientName] = clientNameMetric
						} else {
							var (
								serverDisplayName = displayName
								clientDisplayName = displayName
							)
							if config.Cfg.Language == "en" {
								serverDisplayName = ckcommon.TagServerEnPrefix + " " + displayName
								clientDisplayName = ckcommon.TagClientEnPrefix + " " + displayName
							} else if config.Cfg.Language == "ch" {
								if letterRegexp.MatchString(serverName) {
									serverDisplayName = ckcommon.TagServerChPrefix + " " + displayName
									clientDisplayName = ckcommon.TagClientChPrefix + " " + displayName
								} else {
									serverDisplayName = ckcommon.TagServerChPrefix + displayName
									clientDisplayName = ckcommon.TagClientChPrefix + displayName
								}
							}
							serverNameMetric := NewMetrics(
								0, serverNameDBField, serverDisplayName, "", METRICS_TYPE_NAME_MAP["tag"],
								"Tag", permissions, "", table, "",
							)
							clientNameMetric := NewMetrics(
								0, clientNameDBField, clientDisplayName, "", METRICS_TYPE_NAME_MAP["tag"],
								"Tag", permissions, "", table, "",
							)
							newAllMetrics[serverName] = serverNameMetric
							newAllMetrics[clientName] = clientNameMetric
						}
					} else {
						nameMetric := NewMetrics(
							0, nameDBField, displayName, "", METRICS_TYPE_NAME_MAP["tag"],
							"Tag", permissions, "", table, "",
						)
						newAllMetrics[name] = nameMetric
					}
				}
			}
		}
	}
	metric, ok := newAllMetrics[field]
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
	return map[string]*Metrics{}, err
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

func GetPrometheusSingleTagTranslator(tag, table string) (string, string, error) {
	labelType := ""
	TagTranslatorStr := ""
	nameNoPreffix := strings.TrimPrefix(tag, "tag.")
	metricID, ok := trans_prometheus.Prometheus.MetricNameToID[table]
	if !ok {
		errorMessage := fmt.Sprintf("%s not found", table)
		return "", "", common.NewError(common.RESOURCE_NOT_FOUND, errorMessage)
	}
	labelNameID, ok := trans_prometheus.Prometheus.LabelNameToID[nameNoPreffix]
	if !ok {
		errorMessage := fmt.Sprintf("%s not found", nameNoPreffix)
		return "", "", errors.New(errorMessage)
	}
	// Determine whether the tag is app_label or target_label
	isAppLabel := false
	if appLabels, ok := trans_prometheus.Prometheus.MetricAppLabelLayout[table]; ok {
		for _, appLabel := range appLabels {
			if appLabel.AppLabelName == nameNoPreffix {
				isAppLabel = true
				labelType = "app"
				TagTranslatorStr = fmt.Sprintf("dictGet(flow_tag.app_label_map, 'label_value', (%d, app_label_value_id_%d))", labelNameID, appLabel.AppLabelColumnIndex)
				break
			}
		}
	}
	if !isAppLabel {
		labelType = "target"
		TagTranslatorStr = fmt.Sprintf("dictGet(flow_tag.target_label_map, 'label_value', (%d, %d, target_id))", metricID, labelNameID)
	}
	return TagTranslatorStr, labelType, nil
}

func GetPrometheusAllTagTranslator(table string) (string, error) {
	tagTranslatorStr := ""
	appLabelTranslatorStr := ""
	if appLabels, ok := trans_prometheus.Prometheus.MetricAppLabelLayout[table]; ok {
		// appLabel
		appLabelTranslatorSlice := []string{}
		for _, appLabel := range appLabels {
			if labelNameID, ok := trans_prometheus.Prometheus.LabelNameToID[appLabel.AppLabelName]; ok {
				appLabelTranslator := fmt.Sprintf("'%s',dictGet(flow_tag.app_label_map, 'label_value', (%d, app_label_value_id_%d))", appLabel.AppLabelName, labelNameID, appLabel.AppLabelColumnIndex)
				appLabelTranslatorSlice = append(appLabelTranslatorSlice, appLabelTranslator)
			}
		}
		appLabelTranslatorStr = strings.Join(appLabelTranslatorSlice, ",")
	}

	// targetLabel
	targetLabelTranslatorStr := "CAST((splitByString(', ', dictGet(flow_tag.prometheus_target_label_layout_map, 'target_label_names', target_id)), splitByString(', ', dictGet(flow_tag.prometheus_target_label_layout_map, 'target_label_values', target_id))), 'Map(String, String)')"
	if appLabelTranslatorStr != "" {
		tagTranslatorStr = "toJSONString(mapUpdate(map(" + appLabelTranslatorStr + ")," + targetLabelTranslatorStr + "))"
	} else {
		tagTranslatorStr = "toJSONString(" + targetLabelTranslatorStr + ")"
	}
	return tagTranslatorStr, nil
}

func GetTagDBField(name, db, table string) (string, error) {
	selectTag := name
	tagTranslatorStr := name
	tagItem, ok := tag.GetTag(strings.Trim(name, "`"), db, table, "default")
	if !ok {
		name := strings.Trim(name, "`")
		if strings.HasPrefix(name, "k8s.label.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("k8s_label_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("k8s_label_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("k8s_label", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "k8s.label.")
			tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix, nameNoPreffix, nameNoPreffix)
		} else if strings.HasPrefix(name, "k8s.annotation.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("k8s_annotation_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("k8s_annotation_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("k8s_annotation", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "k8s.annotation.")
			tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix, nameNoPreffix, nameNoPreffix)
		} else if strings.HasPrefix(name, "k8s.env.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("k8s_env_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("k8s_env_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("k8s_env", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "k8s.env.")
			tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
		} else if strings.HasPrefix(name, "cloud.tag.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("cloud_tag_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("cloud_tag_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("cloud_tag", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "cloud.tag.")
			tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix, nameNoPreffix, nameNoPreffix)
		} else if strings.HasPrefix(name, "os.app.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("os_app_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("os_app_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("os_app", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "os.app.")
			tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
		} else if strings.HasPrefix(name, "tag.") || strings.HasPrefix(name, "attribute.") {
			if strings.HasPrefix(name, "tag.") {
				if db == ckcommon.DB_NAME_PROMETHEUS {
					tagTranslatorStr, _, err := GetPrometheusSingleTagTranslator(name, table)
					if err != nil {
						return tagTranslatorStr, err
					}
				}
				tagItem, ok = tag.GetTag("tag.", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("attribute.", db, table, "default")
			}
			nameNoPreffix := strings.TrimPrefix(name, "tag.")
			nameNoPreffix = strings.TrimPrefix(nameNoPreffix, "attribute.")
			tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
		}
	} else {
		if name == "metrics" {
			if db == "flow_log" {
				tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, "metrics_names", "metrics_values")
			} else {
				tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, "metrics_float_names", "metrics_float_values")
			}
		} else if name == "tag" && db == ckcommon.DB_NAME_PROMETHEUS {
			tagTranslatorStr, err := GetPrometheusAllTagTranslator(table)
			if err != nil {
				return tagTranslatorStr, err
			}
		} else if tagItem.TagTranslator != "" {
			if name != "packet_batch" || table != "l4_packet" {
				tagTranslatorStr = tagItem.TagTranslator
			}
		} else {
			tagTranslatorStr = selectTag
		}
	}
	return tagTranslatorStr, nil
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
