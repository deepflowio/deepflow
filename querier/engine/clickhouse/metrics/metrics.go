package metrics

const METRICS_OPERATOR_GTE = ">="
const METRICS_OPERATOR_LTE = "<="

var METRICS_OPERATORS = []string{METRICS_OPERATOR_GTE, METRICS_OPERATOR_LTE}

type Metrics struct {
	DBField     string // 数据库字段
	DisplayName string // 描述
	Unit        string // 单位
	Type        int    // 指标量类型
	Category    string // 类别
	Condition   string // 聚合过滤
}

func (m *Metrics) Replace(metrics *Metrics) {
	if metrics.DBField != "" {
		m.DBField = metrics.DBField
	}
	if metrics.Condition != "" {
		m.Condition = metrics.Condition
	}
}

func NewMetrics(dbField string, displayname string, unit string, metricType int, category string, condition string) *Metrics {
	return &Metrics{
		DBField:     dbField,
		DisplayName: displayname,
		Unit:        unit,
		Type:        metricType,
		Category:    category,
		Condition:   condition,
	}
}

func NewReplaceMetrics(dbField string, condition string) *Metrics {
	return &Metrics{
		DBField:   dbField,
		Condition: condition,
	}
}

func GetMetrics(field string, db string, table string) (*Metrics, bool) {
	allMetrics := GetMetricsByDBTable(db, table)
	metric, ok := allMetrics[field]
	return metric, ok
}

func GetMetricsByDBTable(db string, table string) map[string]*Metrics {
	switch db {
	case "flow_log":
		switch table {
		case "l4_flow_log":
			return GetL4FlowLogMetrics()
		case "l7_flow_log":
			return GetL7FlowLogMetrics()
		}
	}
	return nil
}

func GetMetricsDescriptions(db string, table string) (map[string][]interface{}, error) {
	metrics := GetMetricsByDBTable(db, table)
	if metrics == nil {
		// TODO: metrics not found
		return nil, nil
	}
	columns := []interface{}{
		"name", "display_name", "unit", "type", "category", "operators",
	}
	var values []interface{}
	for field, metrics := range metrics {
		values = append(values, []interface{}{
			field, metrics.DisplayName, metrics.Unit, metrics.Type, metrics.Category, METRICS_OPERATORS,
		})
	}
	return map[string][]interface{}{
		"columns": columns,
		"values":  values,
	}, nil
}

func LoadMetrics(db string, table string, dbDescription map[string]interface{}) (loadMetrics map[string]*Metrics) {
	tableDate, ok := dbDescription[db]
	if !ok {
		// TODO
		return nil
	}
	if ok {
		metricsData, ok := tableDate.(map[string]interface{})[table]
		if ok {
			loadMetrics = make(map[string]*Metrics)
			for _, metrics := range metricsData.([][]interface{}) {
				// metric类型替换成int
				//metrics[3], ok = METRICS_TYPE_NAME_MAP[metrics[3].(string)]
				metricType := METRICS_TYPE_NAME_MAP[metrics[4].(string)]
				lm := NewMetrics(metrics[1].(string), metrics[2].(string), metrics[3].(string), metricType, metrics[5].(string), "")
				loadMetrics[metrics[0].(string)] = lm
			}
		}
	}
	return loadMetrics
}

func MergeMetrics(db string, table string, loadMetrics map[string]*Metrics) {
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
	}
	if metrics == nil {
		return
	}
	for name, value := range loadMetrics {
		if rm, ok := replaceMetrics[name]; ok && value.DBField == "" {
			value.Replace(rm)
		}
		metrics[name] = value
	}
}
