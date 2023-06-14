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
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
)

const (
	LABEL_NAME_METRICS           = "__name__"
	DB_NAME_EXT_METRICS          = "ext_metrics"
	DB_NAME_DEEPFLOW_SYSTEM      = "deepflow_system"
	DB_NAME_FLOW_METRICS         = "flow_metrics"
	TABLE_NAME_METRICS           = "metrics"
	TABLE_NAME_L7_FLOW_LOG       = "l7_flow_log"
	METRICS_CATEGORY_CARDINALITY = "Cardinality"
)

func getTagValues(args *model.PromMetaParams, ctx context.Context) (result *model.PromQueryResponse, err error) {
	if args.LabelName == LABEL_NAME_METRICS {
		return &model.PromQueryResponse{
			Data: getMetrics(args),
		}, nil
	}
	return result, err
}

func getMetrics(args *model.PromMetaParams) (resp []string) {
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
			extMetrics, _ := metrics.GetExtMetrics(DB_NAME_EXT_METRICS, "", where, args.Context)
			for _, v := range extMetrics {
				resp = append(resp, strings.TrimPrefix(v.DisplayName, "metrics."))
				// append ext_metrics__metrics__prometheus_${metrics_name}
				fieldName := strings.Replace(v.Table, ".", "_", 1) // convert prometheus.xxx to prometheus_xxx
				metricsName := fmt.Sprintf("%s__%s__%s", db, TABLE_NAME_METRICS, fieldName)
				resp = append(resp, metricsName)
			}
		} else {
			for _, table := range tables {
				tableMetrics, _ := metrics.GetMetricsByDBTable(db, table, where, args.Context)
				for field, v := range tableMetrics {
					if v.Category == METRICS_CATEGORY_CARDINALITY {
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
