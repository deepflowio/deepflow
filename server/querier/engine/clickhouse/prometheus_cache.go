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
	for _, _key := range metricNameToIDSqlRst.Values {
		metricNameKey := _key.([]interface{})[0]
		metricIDKey := _key.([]interface{})[1]
		metricName := metricNameKey.(string)
		metricID := metricIDKey.(int)
		METRIC_NAME_TO_ID[metricName] = metricID
	}
	if err != nil {
		log.Error(err)
	}

	appLabelSql := "SELECT metric_id,label_name_id,label_value,label_value_id FROM prometheus.app_label_map"
	appLabelSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: appLabelSql})
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
	}
	if err != nil {
		log.Error(err)
	}

	labelNameToIDSql := "SELECT name,id FROM prometheus.prometheus_label_name_map"
	labelNameToIDSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: labelNameToIDSql})
	for _, _key := range labelNameToIDSqlRst.Values {
		labelNameKey := _key.([]interface{})[0]
		labelNameIDKey := _key.([]interface{})[1]
		labelName := labelNameKey.(string)
		labelNameID := labelNameIDKey.(int)
		LABEL_NAME_TO_ID[labelName] = labelNameID
	}
	if err != nil {
		log.Error(err)
	}

	metricAppLabelLayoutSql := "SELECT metric_name,app_label_name,app_label_column_index FROM prometheus.prometheus_metric_app_label_layout_map"
	metricAppLabelLayoutSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: metricAppLabelLayoutSql})
	for _, _key := range metricAppLabelLayoutSqlRst.Values {
		metricNameKey := _key.([]interface{})[0]
		appLabelNameKey := _key.([]interface{})[1]
		appLabelColumnIndexKey := _key.([]interface{})[2]
		metricName := metricNameKey.(string)
		appLabelName := appLabelNameKey.(string)
		appLabelColumnIndex := appLabelColumnIndexKey.(int)
		METRIC_APP_LABEL_LAYOUT[metricName+", "+appLabelName] = appLabelColumnIndex
	}
	if err != nil {
		log.Error(err)
	}

	targetLabelSql := "SELECT metric_id,label_name_id,label_value,target_id FROM prometheus.target_label_map"
	targetLabelSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: targetLabelSql})
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
	}
	if err != nil {
		log.Error(err)
	}
}
