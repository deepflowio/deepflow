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
	"time"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
)

var Prometheus = &PrometheusMap{}

type PrometheusMap struct {
	MetricNameToID       map[string]int
	MetricAppLabelLayout map[string][]AppLabel
	LabelNameToID        map[string]int
	LabelIDToName        map[int]string
}

type Label struct {
	LabelNameID int
	LabelValue  string
}

type AppLabel struct {
	AppLabelName        string
	appLabelColumnIndex int
}

func GenerateMap() {
	METRIC_NAME_TO_ID := map[string]int{}
	METRIC_APP_LABEL_LAYOUT := map[string][]AppLabel{}
	LABEL_NAME_TO_ID := map[string]int{}
	LABEL_ID_TO_NAME := map[int]string{}
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       "flow_tag",
	}
	metricNameToIDSql := "SELECT name,id FROM flow_tag.prometheus_metric_name_map"
	metricNameToIDSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: metricNameToIDSql})
	if err != nil {
		log.Warning(err)
		return
	}
	metricNameToIDRst := make([]interface{}, len(metricNameToIDSqlRst.Values))
	copy(metricNameToIDRst, metricNameToIDSqlRst.Values)
	for _, _key := range metricNameToIDRst {
		metricNameKey := _key.([]interface{})[0]
		metricIDKey := _key.([]interface{})[1]
		metricName := metricNameKey.(string)
		metricID := metricIDKey.(int)
		METRIC_NAME_TO_ID[metricName] = metricID
	}
	Prometheus.MetricNameToID = METRIC_NAME_TO_ID

	labelNameToIDSql := "SELECT name,id FROM flow_tag.prometheus_label_name_map"
	labelNameToIDSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: labelNameToIDSql})
	if err != nil {
		log.Warning(err)
		return
	}
	labelNameToIDRst := make([]interface{}, len(labelNameToIDSqlRst.Values))
	copy(labelNameToIDRst, labelNameToIDSqlRst.Values)
	for _, _key := range labelNameToIDRst {
		labelNameKey := _key.([]interface{})[0]
		labelNameIDKey := _key.([]interface{})[1]
		labelName := labelNameKey.(string)
		labelNameID := labelNameIDKey.(int)
		LABEL_NAME_TO_ID[labelName] = labelNameID
		LABEL_ID_TO_NAME[labelNameID] = labelName
	}
	Prometheus.LabelIDToName = LABEL_ID_TO_NAME
	Prometheus.LabelNameToID = LABEL_NAME_TO_ID

	metricAppLabelLayoutSql := "SELECT metric_name,app_label_name,app_label_column_index FROM flow_tag.prometheus_metric_app_label_layout_map ORDER BY app_label_column_index"
	metricAppLabelLayoutSqlRst, err := chClient.DoQuery(&client.QueryParams{Sql: metricAppLabelLayoutSql})
	if err != nil {
		log.Warning(err)
		return
	}
	metricAppLabelLayoutRst := make([]interface{}, len(metricAppLabelLayoutSqlRst.Values))
	copy(metricAppLabelLayoutRst, metricAppLabelLayoutSqlRst.Values)
	for _, _key := range metricAppLabelLayoutRst {
		metricNameKey := _key.([]interface{})[0]
		appLabelNameKey := _key.([]interface{})[1]
		appLabelColumnIndexKey := _key.([]interface{})[2]
		metricName := metricNameKey.(string)
		appLabelName := appLabelNameKey.(string)
		appLabelColumnIndex := appLabelColumnIndexKey.(int)
		appLabel := AppLabel{AppLabelName: appLabelName, appLabelColumnIndex: appLabelColumnIndex}
		METRIC_APP_LABEL_LAYOUT[metricName] = append(METRIC_APP_LABEL_LAYOUT[metricName], appLabel)
	}
	Prometheus.MetricAppLabelLayout = METRIC_APP_LABEL_LAYOUT
}

func GeneratePrometheusMap() {
	GenerateMap()
	interval := time.Duration(config.Cfg.PrometheusCacheUpdateInterval) * time.Second
	for range time.Tick(interval) {
		GenerateMap()
	}
}
