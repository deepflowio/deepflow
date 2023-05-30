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

package clickhouse

import (
	"fmt"

	// "github.com/deepflowio/deepflow/server/querier/engine/clickhouse"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
)

var METRIC_NAME_TO_ID = map[string]int{}
var APP_LABEL = map[string][]interface{}{}
var TARGET_LABEL = map[string]string{}
var METRIC_APP_LABEL_LAYOUT = map[string]int{}
var LABEL_NAME_TO_ID = map[string]int{}
var LABEL_ID_TO_NAME = map[int]string{}
var METRIC_NAME_TO_MAX_INDEX = map[string]int{}
var METRIC_ID_TARGET_ID_TO_LABELS = map[string][]Label{}
var METRIC_ID_APP_LABEL_VALUE_ID_TO_LABELS = map[string][]Label{}

type Label struct {
	LabelNameID int
	LabelValue  string
}

func GenerateMap() {
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       "prometheus",
	}
	metricNameToIDSql := "SELECT name,id FROM prometheus.prometheus_metric_name_map"
	metricNameToIDSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: metricNameToIDSql})
	if err != nil {
		log.Error(err)
		return
	}
	for _, _key := range metricNameToIDSqlRst.Values {
		metricNameKey := _key.([]interface{})[0]
		metricIDKey := _key.([]interface{})[1]
		metricName := metricNameKey.(string)
		metricID := metricIDKey.(int)
		METRIC_NAME_TO_ID[metricName] = metricID
	}

	appLabelSql := "SELECT metric_id,label_name_id,label_value,label_value_id FROM prometheus.app_label_map"
	appLabelSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: appLabelSql})
	if err != nil {
		log.Error(err)
		return
	}
	for _, _key := range appLabelSqlRst.Values {
		metricIDKey := _key.([]interface{})[0]
		labelNameIDKey := _key.([]interface{})[1]
		labelValueKey := _key.([]interface{})[2]
		labelValueIDKey := _key.([]interface{})[3]
		metricID := metricIDKey.(int)
		labelNameID := labelNameIDKey.(int)
		labelValue := labelValueKey.(string)
		labelValueID := labelValueIDKey.(int)
		APP_LABEL[fmt.Sprintf("%d,%d", metricID, labelNameID)] = []interface{}{labelValueID, labelValue}
		label := Label{LabelNameID: labelNameID, LabelValue: labelValue}
		metricIDAppLabelValueIDKey := fmt.Sprintf("%d,%d", metricID, labelValueID)
		METRIC_ID_APP_LABEL_VALUE_ID_TO_LABELS[metricIDAppLabelValueIDKey] = append(METRIC_ID_APP_LABEL_VALUE_ID_TO_LABELS[metricIDAppLabelValueIDKey], label)
	}

	labelNameToIDSql := "SELECT name,id FROM prometheus.prometheus_label_name_map"
	labelNameToIDSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: labelNameToIDSql})
	if err != nil {
		log.Error(err)
		return
	}
	for _, _key := range labelNameToIDSqlRst.Values {
		labelNameKey := _key.([]interface{})[0]
		labelNameIDKey := _key.([]interface{})[1]
		labelName := labelNameKey.(string)
		labelNameID := labelNameIDKey.(int)
		LABEL_NAME_TO_ID[labelName] = labelNameID
		LABEL_ID_TO_NAME[labelNameID] = labelName
	}

	metricAppLabelLayoutSql := "SELECT metric_name,app_label_name,app_label_column_index FROM prometheus.prometheus_metric_app_label_layout_map"
	metricAppLabelLayoutSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: metricAppLabelLayoutSql})
	if err != nil {
		log.Error(err)
		return
	}
	for _, _key := range metricAppLabelLayoutSqlRst.Values {
		metricNameKey := _key.([]interface{})[0]
		appLabelNameKey := _key.([]interface{})[1]
		appLabelColumnIndexKey := _key.([]interface{})[2]
		metricName := metricNameKey.(string)
		appLabelName := appLabelNameKey.(string)
		appLabelColumnIndex := appLabelColumnIndexKey.(int)
		METRIC_APP_LABEL_LAYOUT[metricName+", "+appLabelName] = appLabelColumnIndex
	}

	targetLabelSql := "SELECT metric_id,label_name_id,label_value,target_id FROM prometheus.target_label_map"
	targetLabelSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: targetLabelSql})
	if err != nil {
		log.Error(err)
		return
	}
	for _, _key := range targetLabelSqlRst.Values {
		metricIDKey := _key.([]interface{})[0]
		labelNameIDKey := _key.([]interface{})[1]
		labelValueKey := _key.([]interface{})[2]
		targetIDKey := _key.([]interface{})[3]
		metricID := metricIDKey.(int)
		labelNameID := labelNameIDKey.(int)
		labelValue := labelValueKey.(string)
		targetID := targetIDKey.(int)
		TARGET_LABEL[fmt.Sprintf("%d,%d,%d", metricID, targetID, labelNameID)] = labelValue
		label := Label{LabelNameID: labelNameID, LabelValue: labelValue}
		metricIDTargetIDKey := fmt.Sprintf("%d,%d", metricID, targetID)
		METRIC_ID_TARGET_ID_TO_LABELS[metricIDTargetIDKey] = append(METRIC_ID_TARGET_ID_TO_LABELS[metricIDTargetIDKey], label)
	}

	metricNameToMaxIndexSql := "SELECT metric_name,max(app_label_column_index) FROM prometheus.prometheus_metric_app_label_layout_map"
	metricNameToMaxIndexSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: metricNameToMaxIndexSql})
	if err != nil {
		log.Error(err)
		return
	}
	for _, _key := range metricNameToMaxIndexSqlRst.Values {
		metricNameKey := _key.([]interface{})[0]
		maxIndexKey := _key.([]interface{})[1]
		metricName := metricNameKey.(string)
		maxIndex := maxIndexKey.(int)
		METRIC_NAME_TO_MAX_INDEX[metricName] = maxIndex
	}
}
