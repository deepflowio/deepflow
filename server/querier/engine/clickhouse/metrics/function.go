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
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

type Function struct {
	Name                    string
	Type                    int
	SupportMetricsTypes     []int  // 支持的指标量类型
	UnitOverwrite           string // 单位替换
	AdditionnalParamCount   int    // 额外参数数量
	IsSupportOtherOperators bool   // 是否支持前置或后置算子
}

func NewFunction(name string, functionType int, supportMetricsTypes []int, unitOverwrite string, additionnalParamCount int, isSupportOtherOperators bool) *Function {
	return &Function{
		Name:                    name,
		Type:                    functionType,
		SupportMetricsTypes:     supportMetricsTypes,
		UnitOverwrite:           unitOverwrite,
		AdditionnalParamCount:   additionnalParamCount,
		IsSupportOtherOperators: isSupportOtherOperators,
	}
}

var METRICS_FUNCTIONS = []string{
	view.FUNCTION_AVG, view.FUNCTION_AAVG, view.FUNCTION_SUM, view.FUNCTION_MAX, view.FUNCTION_MIN,
	view.FUNCTION_PCTL, view.FUNCTION_PCTL_EXACT, view.FUNCTION_SPREAD,
	view.FUNCTION_RSPREAD, view.FUNCTION_STDDEV, view.FUNCTION_APDEX,
	view.FUNCTION_UNIQ, view.FUNCTION_UNIQ_EXACT, view.FUNCTION_PERCENTAG,
	view.FUNCTION_PERSECOND, view.FUNCTION_HISTOGRAM, view.FUNCTION_LAST, view.FUNCTION_COUNT,
	view.FUNCTION_TOPK, view.FUNCTION_ANY,
}

var METRICS_FUNCTIONS_MAP = map[string]*Function{
	view.FUNCTION_COUNT:      NewFunction(view.FUNCTION_COUNT, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_OTHER}, "$unit", 0, true),
	view.FUNCTION_SUM:        NewFunction(view.FUNCTION_SUM, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER}, "$unit", 0, true),
	view.FUNCTION_AVG:        NewFunction(view.FUNCTION_AVG, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "$unit", 0, true),
	view.FUNCTION_AAVG:       NewFunction(view.FUNCTION_AAVG, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "$unit", 0, true),
	view.FUNCTION_MAX:        NewFunction(view.FUNCTION_MAX, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "$unit", 0, true),
	view.FUNCTION_MIN:        NewFunction(view.FUNCTION_MIN, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "$unit", 0, true),
	view.FUNCTION_STDDEV:     NewFunction(view.FUNCTION_STDDEV, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "$unit", 0, true),
	view.FUNCTION_SPREAD:     NewFunction(view.FUNCTION_SPREAD, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "$unit", 0, true),
	view.FUNCTION_RSPREAD:    NewFunction(view.FUNCTION_RSPREAD, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "", 0, true),
	view.FUNCTION_APDEX:      NewFunction(view.FUNCTION_APDEX, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_DELAY}, "%", 1, true),
	view.FUNCTION_PCTL:       NewFunction(view.FUNCTION_PCTL, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "$unit", 1, true),
	view.FUNCTION_PCTL_EXACT: NewFunction(view.FUNCTION_PCTL_EXACT, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "$unit", 1, true),
	view.FUNCTION_UNIQ:       NewFunction(view.FUNCTION_UNIQ, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_TAG}, "$unit", 0, false),
	view.FUNCTION_UNIQ_EXACT: NewFunction(view.FUNCTION_UNIQ_EXACT, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_TAG}, "$unit", 0, false),
	view.FUNCTION_PERCENTAG:  NewFunction(view.FUNCTION_PERCENTAG, FUNCTION_TYPE_MATH, nil, "%", 0, true),
	view.FUNCTION_PERSECOND:  NewFunction(view.FUNCTION_PERSECOND, FUNCTION_TYPE_MATH, nil, "$unit/s", 0, true),
	view.FUNCTION_HISTOGRAM:  NewFunction(view.FUNCTION_HISTOGRAM, FUNCTION_TYPE_MATH, nil, "", 1, true),
	view.FUNCTION_LAST:       NewFunction(view.FUNCTION_LAST, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER, METRICS_TYPE_GAUGE, METRICS_TYPE_DELAY, METRICS_TYPE_PERCENTAGE, METRICS_TYPE_QUOTIENT, METRICS_TYPE_BOUNDED_GAUGE}, "", 0, true),
	view.FUNCTION_TOPK:       NewFunction(view.FUNCTION_TOPK, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_TAG}, "$unit", 1, false),
	view.FUNCTION_ANY:        NewFunction(view.FUNCTION_ANY, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_TAG}, "$unit", 0, false),
	view.FUNCTION_DERIVATIVE: NewFunction(view.FUNCTION_DERIVATIVE, FUNCTION_TYPE_AGG, []int{METRICS_TYPE_COUNTER}, "$unit", 0, true),
}

func GetFunctionDescriptions() (*common.Result, error) {
	columns := []interface{}{
		"name", "type", "support_metric_types", "unit_overwrite", "additional_param_count", "is_support_other_operators",
	}
	var values []interface{}
	for _, name := range METRICS_FUNCTIONS {
		f := METRICS_FUNCTIONS_MAP[name]
		values = append(values, []interface{}{
			f.Name, f.Type, f.SupportMetricsTypes, f.UnitOverwrite, f.AdditionnalParamCount, f.IsSupportOtherOperators,
		})
	}
	return &common.Result{
		Columns: columns,
		Values:  values,
	}, nil
}
