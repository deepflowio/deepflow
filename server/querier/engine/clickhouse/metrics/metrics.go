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
	TagType     string // Tag type of metric's tag type
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
	permissions []bool, condition string, table string, description string, tagType string,
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
		TagType:     tagType,
	}
}

func NewReplaceMetrics(dbField string, condition string) *Metrics {
	return &Metrics{
		DBField:   dbField,
		Condition: condition,
		IsAgg:     true,
	}
}

func GetAggMetrics(field, db, table, orgID string) (*Metrics, bool) {
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
	return GetMetrics(field, db, table, orgID)
}

func GetTagTypeMetrics(tagDescriptions *common.Result, newAllMetrics map[string]*Metrics, db, table, orgID string) error {
	for _, tagValue := range tagDescriptions.Values {
		tagSlice := tagValue.([]interface{})
		name := tagSlice[0].(string)
		clientName := tagSlice[1].(string)
		serverName := tagSlice[2].(string)
		displayName := tagSlice[3].(string)
		tagType := tagSlice[4].(string)
		permissions := tagSlice[7].([]bool)

		if slices.Contains([]string{"auto_custom_tag", "time", "id"}, tagType) {
			continue
		}
		if db == ckcommon.DB_NAME_FLOW_TAG {
			continue
		}
		if name == "lb_listener" || name == "pod_ingress" {
			continue
		}
		if len(tagSlice) >= 12 {
			notSupportedOperators := tagSlice[11].([]string)
			// not support select
			if slices.Contains(notSupportedOperators, "select") {
				continue
			}
		}
		nameDBField, err := GetTagDBField(name, db, table, orgID)
		if err != nil {
			return err
		}
		clientNameDBField, err := GetTagDBField(clientName, db, table, orgID)
		if err != nil {
			return err
		}
		serverNameDBField, err := GetTagDBField(serverName, db, table, orgID)
		if err != nil {
			return err
		}
		if slices.Contains([]string{"l4_flow_log", "l7_flow_log", "application_map", "network_map"}, table) {
			if serverName == clientName {
				clientNameMetric := NewMetrics(
					0, clientNameDBField, displayName, "", METRICS_TYPE_NAME_MAP["tag"],
					"Tag", permissions, "", table, "", tagType,
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
					"Tag", permissions, "", table, "", tagType,
				)
				clientNameMetric := NewMetrics(
					0, clientNameDBField, clientDisplayName, "", METRICS_TYPE_NAME_MAP["tag"],
					"Tag", permissions, "", table, "", tagType,
				)
				newAllMetrics[serverName] = serverNameMetric
				newAllMetrics[clientName] = clientNameMetric
			}
		} else {
			nameMetric := NewMetrics(
				0, nameDBField, displayName, "", METRICS_TYPE_NAME_MAP["tag"],
				"Tag", permissions, "", table, "", tagType,
			)
			newAllMetrics[name] = nameMetric
		}
	}
	return nil
}

func GetMetrics(field, db, table, orgID string) (*Metrics, bool) {
	newAllMetrics := map[string]*Metrics{}
	field = strings.Trim(field, "`")
	if slices.Contains([]string{ckcommon.DB_NAME_EXT_METRICS, ckcommon.DB_NAME_DEEPFLOW_ADMIN, ckcommon.DB_NAME_DEEPFLOW_TENANT, ckcommon.DB_NAME_APPLICATION_LOG}, db) || table == "l7_flow_log" {
		fieldSplit := strings.Split(field, ".")
		if len(fieldSplit) > 1 {
			if fieldSplit[0] == "metrics" {
				fieldName := strings.Replace(field, "metrics.", "", 1)
				metrics_names_field, metrics_values_field := METRICS_ARRAY_NAME_MAP[db][0], METRICS_ARRAY_NAME_MAP[db][1]
				metric := NewMetrics(
					0, fmt.Sprintf("if(indexOf(%s, '%s')=0,null,%s[indexOf(%s, '%s')])", metrics_names_field, fieldName, metrics_values_field, metrics_names_field, fieldName),
					field, "", METRICS_TYPE_COUNTER,
					"metrics", []bool{true, true, true}, "", table, "", "",
				)
				newAllMetrics[field] = metric
			}
		}
	} else if db == ckcommon.DB_NAME_PROMETHEUS {
		metric := NewMetrics(
			0, field,
			field, "", METRICS_TYPE_COUNTER,
			"metrics", []bool{true, true, true}, "", table, "", "",
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
	tagDescriptions, err := tag.GetTagDescriptions(db, table, "", "", orgID, true, context.Background())
	if err != nil {
		log.Error("Failed to get tag type metrics")
		return nil, false
	}
	GetTagTypeMetrics(tagDescriptions, newAllMetrics, db, table, orgID)
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
		case "network":
			return GetVtapFlowPortMetrics(), err
		case "network_map":
			return GetVtapFlowEdgePortMetrics(), err
		case "application":
			return GetVtapAppPortMetrics(), err
		case "application_map":
			return GetVtapAppEdgePortMetrics(), err
		case "traffic_policy":
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
	case ckcommon.DB_NAME_APPLICATION_LOG:
		switch table {
		case "log":
			return GetLogMetrics(), err
		}
	}
	return map[string]*Metrics{}, err
}

func GetMetricsByDBTable(db, table, where, queryCacheTTL, orgID string, useQueryCache bool, ctx context.Context) (map[string]*Metrics, error) {
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
			exts, err := GetExtMetrics(db, table, where, queryCacheTTL, orgID, useQueryCache, ctx)
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
				"metrics", []bool{true, true, true}, "", table, "", "",
			)
			return metrics, err
		}
	case "flow_metrics":
		switch table {
		case "network":
			return GetVtapFlowPortMetrics(), err
		case "network_map":
			return GetVtapFlowEdgePortMetrics(), err
		case "application":
			return GetVtapAppPortMetrics(), err
		case "application_map":
			return GetVtapAppEdgePortMetrics(), err
		case "traffic_policy":
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
	case ckcommon.DB_NAME_APPLICATION_LOG:
		switch table {
		case "log":
			metrics := make(map[string]*Metrics)
			loads := GetLogMetrics()
			exts, err := GetExtMetrics(db, table, where, queryCacheTTL, orgID, useQueryCache, ctx)
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
				"metrics", []bool{true, true, true}, "", table, "", "",
			)
			return metrics, err
		}
	case ckcommon.DB_NAME_EXT_METRICS, ckcommon.DB_NAME_DEEPFLOW_ADMIN, ckcommon.DB_NAME_DEEPFLOW_TENANT:
		return GetExtMetrics(db, table, where, queryCacheTTL, orgID, useQueryCache, ctx)
	case ckcommon.DB_NAME_PROMETHEUS:
		return GetPrometheusMetrics(db, table, where, queryCacheTTL, orgID, useQueryCache, ctx)
	}

	return nil, err
}

func GetMetricsDescriptionsByDBTable(db, table, where, queryCacheTTL, orgID string, useQueryCache bool, ctx context.Context) ([]interface{}, error) {
	allMetrics, err := GetMetricsByDBTable(db, table, where, queryCacheTTL, orgID, useQueryCache, ctx)
	if allMetrics == nil || err != nil {
		// TODO: metrics not found
		return nil, err
	}
	/* columns := []interface{}{
		"name", "is_agg", "display_name", "unit", "type", "category", "operators", "permissions", "table"
	} */
	values := make([]interface{}, len(allMetrics))
	for field, metrics := range allMetrics {

		if slices.Contains([]string{ckcommon.DB_NAME_EXT_METRICS, ckcommon.DB_NAME_DEEPFLOW_ADMIN, ckcommon.DB_NAME_DEEPFLOW_TENANT}, db) || (table == "l7_flow_log" && strings.Contains(field, "metrics.")) {
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

func GetMetricsDescriptions(db, table, where, queryCacheTTL, orgID string, useQueryCache bool, ctx context.Context) (*common.Result, error) {
	var values []interface{}
	if table == "" && db != ckcommon.DB_NAME_PROMETHEUS {
		var tables []interface{}
		if db == "ext_metrics" {
			tables = append(tables, table)
		} else if slices.Contains([]string{ckcommon.DB_NAME_DEEPFLOW_ADMIN, ckcommon.DB_NAME_DEEPFLOW_TENANT}, db) {
			for _, extTables := range ckcommon.GetExtTables(db, queryCacheTTL, orgID, useQueryCache, ctx) {
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
			metrics, err := GetMetricsDescriptionsByDBTable(db, dbTable.(string), where, queryCacheTTL, orgID, useQueryCache, ctx)
			if err != nil {
				return nil, err
			}
			values = append(values, metrics...)
		}
	} else {
		metrics, err := GetMetricsDescriptionsByDBTable(db, table, where, queryCacheTTL, orgID, useQueryCache, ctx)
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

func GetPrometheusSingleTagTranslator(tag, table, orgID string) (string, string, error) {
	labelType := ""
	TagTranslatorStr := ""
	nameNoPreffix := strings.TrimPrefix(tag, "tag.")
	metricID, ok := trans_prometheus.ORGPrometheus[orgID].MetricNameToID[table]
	if !ok {
		errorMessage := fmt.Sprintf("%s not found", table)
		return "", "", common.NewError(common.RESOURCE_NOT_FOUND, errorMessage)
	}
	labelNameID, ok := trans_prometheus.ORGPrometheus[orgID].LabelNameToID[nameNoPreffix]
	if !ok {
		errorMessage := fmt.Sprintf("%s not found", nameNoPreffix)
		return "", "", errors.New(errorMessage)
	}
	// Determine whether the tag is app_label or target_label
	isAppLabel := false
	if appLabels, ok := trans_prometheus.ORGPrometheus[orgID].MetricAppLabelLayout[table]; ok {
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

func GetPrometheusAllTagTranslator(table, orgID string) (string, error) {
	tagTranslatorStr := ""
	appLabelTranslatorStr := ""
	if appLabels, ok := trans_prometheus.ORGPrometheus[orgID].MetricAppLabelLayout[table]; ok {
		// appLabel
		appLabelTranslatorSlice := []string{}
		for _, appLabel := range appLabels {
			if labelNameID, ok := trans_prometheus.ORGPrometheus[orgID].LabelNameToID[appLabel.AppLabelName]; ok {
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

func GetTagDBField(name, db, table, orgID string) (string, error) {
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
					tagTranslatorStr, _, err := GetPrometheusSingleTagTranslator(name, table, orgID)
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
			if db == "flow_log" || db == ckcommon.DB_NAME_APPLICATION_LOG {
				tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, "metrics_names", "metrics_values")
			} else {
				tagTranslatorStr = fmt.Sprintf(tagItem.TagTranslator, "metrics_float_names", "metrics_float_values")
			}
		} else if name == "tag" && db == ckcommon.DB_NAME_PROMETHEUS {
			tagTranslatorStr, err := GetPrometheusAllTagTranslator(table, orgID)
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
					metrics[3].(string), permissions, "", table, description, "",
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
		case "network":
			metrics = VTAP_FLOW_PORT_METRICS
			replaceMetrics = VTAP_FLOW_PORT_METRICS_REPLACE
		case "network_map":
			metrics = VTAP_FLOW_EDGE_PORT_METRICS
			replaceMetrics = VTAP_FLOW_EDGE_PORT_METRICS_REPLACE
		case "application":
			metrics = VTAP_APP_PORT_METRICS
			replaceMetrics = VTAP_APP_PORT_METRICS_REPLACE
		case "application_map":
			metrics = VTAP_APP_EDGE_PORT_METRICS
			replaceMetrics = VTAP_APP_EDGE_PORT_METRICS_REPLACE
		case "traffic_policy":
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
	case ckcommon.DB_NAME_APPLICATION_LOG:
		switch table {
		case "log":
			metrics = LOG_METRICS
			replaceMetrics = LOG_METRICS_REPLACE
		}
	case ckcommon.DB_NAME_PROMETHEUS:
		metrics = PROMETHEUS_METRICS
		replaceMetrics = PROMETHEUS_METRICS_REPLACE

	case ckcommon.DB_NAME_EXT_METRICS, ckcommon.DB_NAME_DEEPFLOW_ADMIN, ckcommon.DB_NAME_DEEPFLOW_TENANT:
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
