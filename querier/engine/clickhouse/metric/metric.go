package metric

const METRIC_OPERATOR_GTE = ">="
const METRIC_OPERATOR_LTE = "<="

var METRIC_OPERATORS = []string{METRIC_OPERATOR_GTE, METRIC_OPERATOR_LTE}

type Metric struct {
	DBField     string // 数据库字段
	DisplayName string // 描述
	Unit        string // 单位
	Type        int    // 指标量类型
	Category    string // 类别
	Condition   string // 聚合过滤
}

func (m *Metric) Replace(metric *Metric) {
	if metric.DBField != "" {
		m.DBField = metric.DBField
	}
	if metric.Condition != "" {
		m.Condition = metric.Condition
	}
}

func NewMetric(dbField string, displayname string, unit string, metricType int, category string, condition string) *Metric {
	return &Metric{
		DBField:     dbField,
		DisplayName: displayname,
		Unit:        unit,
		Type:        metricType,
		Category:    category,
		Condition:   condition,
	}
}

func NewReplaceMetric(dbField string, condition string) *Metric {
	return &Metric{
		DBField:   dbField,
		Condition: condition,
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
			return GetL4FlowLogMetrics()
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
		"name", "display_name", "unit", "type", "category", "operators",
	}
	var values []interface{}
	for field, metric := range metrics {
		values = append(values, []interface{}{
			field, metric.DisplayName, metric.Unit, metric.Type, metric.Category, METRIC_OPERATORS,
		})
	}
	return map[string][]interface{}{
		"columns": columns,
		"values":  values,
	}, nil
}

func LoadMetrics(db string, table string, dbDescriptions map[string]interface{}) (loadMetrics map[string]*Metric) {
	metricData, ok := dbDescriptions["metric"]
	if !ok {
		// TODO
		return nil
	}
	tableDate, ok := metricData.(map[string]interface{})[db]
	if !ok {
		// TODO
		return nil
	}
	if ok {
		metricData, ok := tableDate.(map[string]interface{})[table]
		if ok {
			loadMetrics = make(map[string]*Metric)
			for _, metric := range metricData.([][]interface{}) {
				// metric类型替换成int
				//metric[3], ok = METRIC_TYPE_NAME_MAP[metric[3].(string)]
				metricType := METRIC_TYPE_NAME_MAP[metric[4].(string)]
				loadMetric := NewMetric(metric[1].(string), metric[2].(string), metric[3].(string), metricType, metric[5].(string), "")
				loadMetrics[metric[0].(string)] = loadMetric
			}
		}
	}
	return loadMetrics
}

func MergeMetrics(db string, table string, loadMetrics map[string]*Metric) {
	var metrics map[string]*Metric
	var replaceMetrics map[string]*Metric
	switch db {
	case "flow_log":
		switch table {
		case "l4_flow_log":
			metrics = L4_FLOW_LOG_METRICS
			replaceMetrics = L4_FLOW_LOG_METRICS_REPLACE
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
