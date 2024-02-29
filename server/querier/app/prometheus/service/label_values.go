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

package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
)

const (
	LABEL_NAME_METRICS      = "__name__"
	DB_NAME_EXT_METRICS     = "ext_metrics"
	DB_NAME_DEEPFLOW_SYSTEM = "deepflow_system"
	DB_NAME_FLOW_METRICS    = "flow_metrics"
	TABLE_NAME_METRICS      = "metrics"
	TABLE_NAME_L7_FLOW_LOG  = "l7_flow_log"
	TABLE_NAME_SAMPLES      = "samples"
	METRICS_CATEGORY_TAG    = "Tag"
)

func (p *prometheusExecutor) getTagValues(ctx context.Context, args *model.PromMetaParams) (result *model.PromQueryResponse, err error) {
	if args.LabelName == LABEL_NAME_METRICS {
		return &model.PromQueryResponse{
			Data: getMetrics(ctx, args),
		}, nil
	}
	return result, err
}

func getMetrics(ctx context.Context, args *model.PromMetaParams) (resp []string) {
	// We speed up the return of the metrics list by querying the aggregation information in
	// `flow_tag.ext_metrics_custom_field_value`. Since we do not query the original time series
	// data, filtering metrics by time is currently not supported.
	where := ""
	//if args.StartTime != "" && args.EndTime != "" {
	//	where = fmt.Sprintf("time>=%s AND time<=%s", args.StartTime, args.EndTime)
	//} else if args.StartTime != "" {
	//	where = fmt.Sprintf("time>=%s", args.StartTime)
	//} else if args.EndTime != "" {
	//	where = fmt.Sprintf("time<=%s", args.EndTime)
	//}

	resp = []string{}
	for db, tables := range chCommon.DB_TABLE_MAP {
		if db == DB_NAME_EXT_METRICS {
			extMetrics, _ := metrics.GetExtMetrics(DB_NAME_EXT_METRICS, "", where, "", false, args.Context)
			for _, v := range extMetrics {
				// append telegraf metrics, e.g.: influxdb_internal_statsd__tcp_current_connections[influxdb_target__metric]
				metricName := fmt.Sprintf("%s__%s__%s__%s", db, "metrics", strings.Replace(v.Table, ".", "_", 1), strings.TrimPrefix(v.DisplayName, "metrics."))
				resp = append(resp, metricName)
			}
		} else if db == chCommon.DB_NAME_PROMETHEUS {
			// prometheus samples should get all metrcis from `table`
			samples := clickhouse.GetTables(db, "", false, ctx)
			for _, v := range samples.Values {
				tableName := v.([]interface{})[0].(string)
				// append ${metrics_name}
				resp = append(resp, tableName)
				// append prometheus__samples__${metrics_name}
				metricsName := fmt.Sprintf("%s__%s__%s", db, TABLE_NAME_SAMPLES, tableName)
				resp = append(resp, metricsName)
			}
		} else if db == DB_NAME_DEEPFLOW_SYSTEM {
			deepflowSystem, _ := metrics.GetExtMetrics(DB_NAME_DEEPFLOW_SYSTEM, "", where, "", false, args.Context)
			for _, v := range deepflowSystem {
				metricName := fmt.Sprintf("%s__%s__%s", db, strings.ReplaceAll(v.Table, ".", "_"), strings.TrimPrefix(v.DisplayName, "metrics."))
				resp = append(resp, metricName)
			}
		} else {
			for _, table := range tables {
				tableMetrics, _ := metrics.GetMetricsByDBTable(db, table, where, "", false, args.Context)
				for field, v := range tableMetrics {
					if v.Category == METRICS_CATEGORY_TAG {
						continue
					}
					if db == DB_NAME_DEEPFLOW_SYSTEM || (table == TABLE_NAME_L7_FLOW_LOG && strings.Contains(field, "metrics.")) {
						field = v.DisplayName
					}
					metricsName := ""
					if db == DB_NAME_FLOW_METRICS {
						metricsName = fmt.Sprintf("%s__%s__%s__%s", db, table, field, "1m")
						resp = append(resp, metricsName)
						metricsName = fmt.Sprintf("%s__%s__%s__%s", db, table, field, "1s")
						resp = append(resp, metricsName)
					} else {
						metricsName = fmt.Sprintf("%s__%s__%s", db, table, field)
						resp = append(resp, metricsName)
					}
				}
			}
		}
	}
	return resp
}
