package prometheus

import (
	"fmt"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/common"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
)

var LABEL_NAME_METRICS = "__name__"
var DB_NAME_EXT_METRICS = "ext_metrics"
var DB_NAME_DEEPFLOW_SYSTEM = "deepflow_system"
var DB_NAME_FLOW_METRICS = "flow_metrics"
var TABLE_NAME_L7_FLOW_LOG = "l7_flow_log"
var METRICS_CATEGORY_CARDINALITY = "Cardinality"

func GetTagValues(args *common.PromMetaParams) (result *common.PromQueryResponse, err error) {
	if args.LabelName == LABEL_NAME_METRICS {
		return &common.PromQueryResponse{
			Data: getMetrics(args),
		}, nil
	}
	return result, err
}

func getMetrics(args *common.PromMetaParams) (resp []string) {
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
