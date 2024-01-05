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
	"testing"

	"github.com/deepflowio/deepflow/server/querier/common"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
)

func TestCheckDBField(t *testing.T) {
	dir := "../../../db_descriptions"
	dbDescriptions, err := common.LoadDbDescriptions(dir)
	if err != nil {
		t.Errorf(err.Error())
	}
	dbData, ok := dbDescriptions["clickhouse"]
	if !ok {
		t.Errorf("clickhouse not in dbDescription")
	}

	dbDataMap := dbData.(map[string]interface{})
	// 加载metric定义
	if metricData, ok := dbDataMap["metrics"]; ok {
		for db, tables := range chCommon.DB_TABLE_MAP {
			for _, table := range tables {
				loadMetrics, err := LoadMetrics(db, table, metricData.(map[string]interface{}))

				if err != nil {
					t.Errorf(err.Error())
				}
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
					}
				}
				if metrics == nil {
					t.Errorf("merge metrics failed! db:%s, table:%s", db, table)
				}
				for name := range replaceMetrics {
					if _, ok := loadMetrics[name]; !ok {
						t.Errorf("replace_metrics: %s not define in db_description", name)
					}
				}
				for name, value := range loadMetrics {
					if value.DBField == "" {
						if _, ok := replaceMetrics[name]; !ok {
							t.Errorf("metrics: %s , DBField not in db_description and DBField not in replace_metrics", name)
						}
					} else {
						if rm, ok := replaceMetrics[name]; ok {
							if rm.DBField != "" {
								t.Errorf("metrics: %s , DBField both in db_description and replace_metrics", name)
							}
						}
					}
				}
			}
		}
	} else {
		t.Errorf("clickhouse not has metrics")
	}
}
