package metric

const (
	L4_FLOW_LOG_CATEGORY_L3_TRAFFIC = "l3-traffic-flow-log"
	L4_FLOW_LOG_CATEGORY_L4_LATENCY = "l4-latency-flow-log"
)

type Metric struct {
	DBField     string // 数据库字段
	DisplayName string // 描述
	Unit        string // 单位
	Type        int    // 指标量类型
	Category    string // 类别
}

func NewMetric(dbField string, displayname string, unit string, metricType int, category string) *Metric {
	return &Metric{
		DBField:     dbField,
		DisplayName: displayname,
		Unit:        unit,
		Type:        metricType,
		Category:    category,
	}
}

func GetMetric(field string, db string, table string) *Metric {
	allMetrics := GetMetricsByDBTable(db, table)
	if metric, ok := allMetrics[field]; ok {
		return metric
	}
	return nil
}

func GetMetricsByDBTable(db string, table string) map[string]*Metric {
	switch db {
	case "flow_log":
		if table == "l4_flow_log" {
			return L4_FLOW_LOG_METRICS
		}
	}
	return nil
}

func GetMetricDescriptions(db string, table string) (map[string][]interface{}, error) {
	metrics := GetMetricsByDBTable(db, table)
	if metrics == nil {
		// TODO: metrics not found
		return nil, nil
	}
	columns := []interface{}{
		"name", "display_name", "unit", "type", "category",
	}
	var values []interface{}
	for field, metric := range metrics {
		values = append(values, []interface{}{
			field, metric.DisplayName, metric.Unit, metric.Type, metric.Category,
		})
	}
	return map[string][]interface{}{
		"columns": columns,
		"values":  values,
	}, nil
}
