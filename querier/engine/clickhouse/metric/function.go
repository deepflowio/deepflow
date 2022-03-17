package metric

import (
	"metaflow/querier/engine/clickhouse/view"
)

type Function struct {
	Name                  string
	Type                  int
	SupportMetricTypes    []int  // 支持的指标量类型
	UnitOverwrite         string // 单位替换
	AdditionnalParamCount int    // 额外参数数量
}

func NewFunction(name string, functionType int, supportMetricTypes []int, unitOverwrite string, additionnalParamCount int) *Function {
	return &Function{
		Name:                  name,
		Type:                  functionType,
		SupportMetricTypes:    supportMetricTypes,
		UnitOverwrite:         unitOverwrite,
		AdditionnalParamCount: additionnalParamCount,
	}
}

var METRIC_FUNCTIONS []*Function = []*Function{
	NewFunction(view.FUNCTION_SUM, FUNCTION_TYPE_AGG, []int{METRIC_TYPE_COUNTER}, "$unit", 0),
	NewFunction(view.FUNCTION_AVG, FUNCTION_TYPE_AGG, []int{METRIC_TYPE_COUNTER, METRIC_TYPE_GAUGE, METRIC_TYPE_DELAY, METRIC_TYPE_PERCENTAGE}, "$unit", 0),
	NewFunction(view.FUNCTION_MAX, FUNCTION_TYPE_AGG, []int{METRIC_TYPE_COUNTER, METRIC_TYPE_GAUGE, METRIC_TYPE_DELAY, METRIC_TYPE_PERCENTAGE}, "$unit", 0),
	NewFunction(view.FUNCTION_MIN, FUNCTION_TYPE_AGG, []int{METRIC_TYPE_COUNTER, METRIC_TYPE_GAUGE, METRIC_TYPE_DELAY, METRIC_TYPE_PERCENTAGE}, "$unit", 0),
	NewFunction(view.FUNCTION_STDDEV, FUNCTION_TYPE_AGG, []int{METRIC_TYPE_COUNTER, METRIC_TYPE_GAUGE, METRIC_TYPE_DELAY, METRIC_TYPE_PERCENTAGE}, "$unit", 0),
	NewFunction(view.FUNCTION_SPREAD, FUNCTION_TYPE_AGG, []int{METRIC_TYPE_COUNTER, METRIC_TYPE_GAUGE, METRIC_TYPE_DELAY, METRIC_TYPE_PERCENTAGE}, "$unit", 0),
	NewFunction(view.FUNCTION_RSPREAD, FUNCTION_TYPE_AGG, []int{METRIC_TYPE_COUNTER, METRIC_TYPE_GAUGE, METRIC_TYPE_DELAY, METRIC_TYPE_PERCENTAGE}, "", 0),
}

func GetFunctionDescriptions() (map[string][]interface{}, error) {
	columns := []interface{}{
		"name", "type", "support_metric_types", "unit_overwrite", "additionnal_param_count",
	}
	var values []interface{}
	for _, f := range METRIC_FUNCTIONS {
		values = append(values, []interface{}{
			f.Name, f.Type, f.SupportMetricTypes, f.UnitOverwrite, f.AdditionnalParamCount,
		})
	}
	return map[string][]interface{}{
		"columns": columns,
		"values":  values,
	}, nil
}
