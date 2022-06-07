package metrics

import (
	"metaflow/querier/common"
	chCommon "metaflow/querier/engine/clickhouse/common"
	"testing"
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
