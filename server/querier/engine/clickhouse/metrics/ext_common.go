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
	"fmt"

	"github.com/deepflowys/deepflow/server/querier/config"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse/client"
)

var EXT_METRICS = map[string]*Metrics{}

func GetExtMetrics(db, table, where string) (map[string]*Metrics, error) {
	loadMetrics := make(map[string]*Metrics)
	var err error
	if db == "ext_metrics" || db == "deepflow_system" {
		externalChClient := client.Client{
			Host:     config.Cfg.Clickhouse.Host,
			Port:     config.Cfg.Clickhouse.Port,
			UserName: config.Cfg.Clickhouse.User,
			Password: config.Cfg.Clickhouse.Password,
			DB:       "flow_tag",
		}
		var externalMetricSql string
		if where != "" {
			externalMetricSql = fmt.Sprintf("SELECT field_name FROM %s_custom_field WHERE table='%s' AND field_type='metrics' AND (%s) GROUP BY field_name ORDER BY field_name ASC", db, table, where)
		} else {
			externalMetricSql = fmt.Sprintf("SELECT field_name FROM %s_custom_field WHERE table='%s' AND field_type='metrics' GROUP BY field_name ORDER BY field_name ASC", db, table)
		}

		externalMetricFloatRst, err := externalChClient.DoQuery(&client.QueryParams{Sql: externalMetricSql})
		if err != nil {
			log.Error(err)
			return nil, err
		}
		for i, _tagName := range externalMetricFloatRst["values"] {
			tagName := _tagName.([]interface{})[0]
			externalTag := tagName.(string)
			dbField := fmt.Sprintf("metrics_float_values[indexOf(metrics_float_names, '%s')]", externalTag)
			lm := NewMetrics(
				i, dbField, externalTag, "", METRICS_TYPE_COUNTER,
				"指标", []bool{true, true, true}, "", table,
			)
			metricName := fmt.Sprintf("%s.%s", "metrics", externalTag)
			loadMetrics[metricName] = lm
		}
	}
	return loadMetrics, err
}
