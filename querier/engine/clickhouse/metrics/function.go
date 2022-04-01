package metrics

import (
	"metaflow/querier/engine/clickhouse/view"
)

type Function struct {
	Name                  string
	Type                  int
	SupportMetricsTypes   []int  // 支持的指标量类型
	UnitOverwrite         string // 单位替换
	AdditionnalParamCount int    // 额外参数数量
}

func NewFunction(name string, functionType int, supportMetricsTypes []int, unitOverwrite string, additionnalParamCount int) *Function {
	return &Function{
		Name:                  name,
		Type:                  functionType,
		SupportMetricsTypes:   supportMetricsTypes,
		UnitOverwrite:         unitOverwrite,
		AdditionnalParamCount: additionnalParamCount,
	}
}

var METRICS_FUNCTIONS = map[string]*Function{
	view.FUNCTION_SUM:        NewFunction(view.FUNCTION_SUM, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER}, "$unit", 0),
	view.FUNCTION_AVG:        NewFunction(view.FUNCTION_AVG, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT}, "$unit", 0),
	view.FUNCTION_MAX:        NewFunction(view.FUNCTION_MAX, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT}, "$unit", 0),
	view.FUNCTION_MIN:        NewFunction(view.FUNCTION_MIN, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT}, "$unit", 0),
	view.FUNCTION_STDDEV:     NewFunction(view.FUNCTION_STDDEV, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT}, "$unit", 0),
	view.FUNCTION_SPREAD:     NewFunction(view.FUNCTION_SPREAD, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT}, "$unit", 0),
	view.FUNCTION_RSPREAD:    NewFunction(view.FUNCTION_RSPREAD, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT}, "", 0),
	view.FUNCTION_APDEX:      NewFunction(view.FUNCTION_APDEX, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_DELAY}, "%", 1),
	view.FUNCTION_PCTL:       NewFunction(view.FUNCTION_PCTL, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT}, "$unit", 1),
	view.FUNCTION_PCTL_EXACT: NewFunction(view.FUNCTION_PCTL_EXACT, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT}, "$unit", 1),
	view.FUNCTION_UNIQ:       NewFunction(view.FUNCTION_UNIQ, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_TAG}, "$unit", 0),
	view.FUNCTION_UNIQ_EXACT: NewFunction(view.FUNCTION_UNIQ_EXACT, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_TAG}, "$unit", 0),
}

func GetFunctionDescriptions() (map[string][]interface{}, error) {
	columns := []interface{}{
		"name", "type", "support_metric_types", "unit_overwrite", "additional_param_count",
	}
	var values []interface{}
	for _, f := range METRICS_FUNCTIONS {
		values = append(values, []interface{}{
			f.Name, f.Type, f.SupportMetricsTypes, f.UnitOverwrite, f.AdditionnalParamCount,
		})
	}
	return map[string][]interface{}{
		"columns": columns,
		"values":  values,
	}, nil
}
