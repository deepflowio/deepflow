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

package metrics

import (
	"context"
	"fmt"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
)

var EXT_METRICS = map[string]*Metrics{}

func GetExtMetrics(db, table, where string, ctx context.Context) (map[string]*Metrics, error) {
	loadMetrics := make(map[string]*Metrics)
	var err error
	if db == "ext_metrics" || db == "deepflow_system" || (db == "flow_log" && table == "l7_flow_log") {
		// Avoid UT failures
		if config.Cfg == nil {
			return nil, nil
		}
		externalChClient := client.Client{
			Host:     config.Cfg.Clickhouse.Host,
			Port:     config.Cfg.Clickhouse.Port,
			UserName: config.Cfg.Clickhouse.User,
			Password: config.Cfg.Clickhouse.Password,
			DB:       "flow_tag",
			Context:  ctx,
		}
		var externalMetricSql string
		var tableFilter string
		var whereSql string
		externalMetricSql = "SELECT field_name, table FROM %s_custom_field WHERE %s field_type='metrics' %s GROUP BY field_name, table ORDER BY table, field_name ASC"
		if table != "" {
			tableFilter = fmt.Sprintf("table='%s' AND", table)
		}
		if where != "" {
			whereSql = fmt.Sprintf("AND (%s)", where)
		}
		externalMetricSql = fmt.Sprintf(externalMetricSql, db, tableFilter, whereSql)

		externalMetricFloatRst, err := externalChClient.DoQuery(&client.QueryParams{Sql: externalMetricSql})
		if err != nil {
			log.Error(err)
			return nil, err
		}
		for i, value := range externalMetricFloatRst.Values {
			tagName := value.([]interface{})[0]
			tableName := value.([]interface{})[1].(string)
			externalTag := tagName.(string)
			metrics_names_field, metrics_values_field := METRICS_ARRAY_NAME_MAP[db][0], METRICS_ARRAY_NAME_MAP[db][1]
			dbField := fmt.Sprintf("if(indexOf(%s, '%s')=0, null, %s[indexOf(%s, '%s')])", metrics_names_field, externalTag, metrics_values_field, metrics_names_field, externalTag)
			metricName := fmt.Sprintf("metrics.%s", externalTag)
			lm := NewMetrics(
				i, dbField, metricName, "", METRICS_TYPE_COUNTER,
				"metrics", []bool{true, true, true}, "", tableName, "",
			)
			loadMetrics[fmt.Sprintf("%s-%s", metricName, tableName)] = lm
		}
	}
	return loadMetrics, err
}
