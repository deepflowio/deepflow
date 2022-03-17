package clickhouse

import (
	"fmt"
	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse/metric"
	"metaflow/querier/engine/clickhouse/view"
	"strings"
)

func GetFunc(name string, args []string, alias string, db string, table string) (Statement, int, error) {
	var levelFlag int
	if len(args) > 0 {
		field := args[0]
		metricStruct := metric.GetMetric(field, db, table)
		// 判断算子是否支持单层
		unlayFuns := metric.METRIC_TYPE_UNLAY_FUNCTIONS[metricStruct.Type]
		if common.IsValueInSliceString(name, unlayFuns) {
			levelFlag = view.MODEL_METRIC_LEVEL_FLAG_UNLAY
		} else {
			levelFlag = view.MODEL_METRIC_LEVEL_FLAG_LAYERED
		}
		if alias == "" {
			alias = GetDefaultAlias(name, args)
		}
		return &Function{
			Metric: metricStruct,
			Name:   name,
			Field:  field,
			Args:   args,
			Alias:  alias,
		}, levelFlag, nil
	}
	return nil, levelFlag, nil
}

func GetDefaultAlias(name string, args []string) string {
	alias := name
	for _, arg := range args {
		alias = fmt.Sprintf("%s_%s", alias, strings.ToLower(arg))
	}
	return alias
}

type Function struct {
	// 指标量内容
	Metric *metric.Metric
	// 解析获得的参数
	Name  string
	Field string
	Args  []string
	Alias string
}

func (f *Function) Format(m *view.Model) {
	if m.MetricLevelFlag == view.MODEL_METRIC_LEVEL_FLAG_LAYERED {
		// 需要拆层
		var outerFields []view.Node
		outFunc := view.GetFunc(f.Name)
		outFunc.SetFlag(view.METRIC_FLAG_OUTER)
		outFunc.SetAlias(f.Alias, false)
		switch f.Metric.Type {
		case metric.METRIC_TYPE_COUNTER:
			// 内层算子使用默认alias
			innerFunction := view.DefaultFunction{
				Name:   view.FUNCTION_SUM,
				Fields: []view.Node{&view.Field{Value: f.Metric.DBField}},
			}
			innerAlias := innerFunction.SetAlias("", true)
			innerFunction.SetFlag(view.METRIC_FLAG_INNER)
			innerFunction.Init()
			m.AddTag(&innerFunction)
			outFunc.SetFillNullAsZero(true)
			// 内层算子的alias作为外层算子的fields传入
			outerFields = append(outerFields, &view.Field{Value: innerAlias})
		case metric.METRIC_TYPE_DELAY:
			innerFunction := view.DefaultFunction{
				Name:       view.FUNCTION_GROUP_ARRAY,
				Fields:     []view.Node{&view.Field{Value: f.Metric.DBField}},
				IgnoreZero: true,
			}
			innerAlias := innerFunction.SetAlias("", true)
			innerFunction.SetFlag(view.METRIC_FLAG_INNER)
			innerFunction.Init()
			m.AddTag(&innerFunction)
			outerFields = append(outerFields, &view.Field{Value: innerAlias})
			outFunc.SetIsGroupArray(true)
			outFunc.SetIgnoreZero(true)
		case metric.METRIC_TYPE_PERCENTAGE:
			innerFunction := view.DefaultFunction{
				Name:       view.FUNCTION_GROUP_ARRAY,
				Fields:     []view.Node{&view.Field{Value: f.Metric.DBField}},
				IgnoreZero: true,
			}
			innerAlias := innerFunction.SetAlias("", true)
			innerFunction.SetFlag(view.METRIC_FLAG_INNER)
			innerFunction.Init()
			m.AddTag(&innerFunction)
			outerFields = append(outerFields, &view.Field{Value: innerAlias})
			outFunc.SetIsGroupArray(true)
			outFunc.SetFillNullAsZero(true)
		}
		outFunc.SetFields(outerFields)
		outFunc.Init()
		m.AddTag(outFunc)
	} else if m.MetricLevelFlag == view.MODEL_METRIC_LEVEL_FLAG_UNLAY {
		// 不需要拆层
		function := view.GetFunc(f.Name)
		function.SetFields([]view.Node{&view.Field{Value: f.Metric.DBField}})
		function.SetFlag(view.METRIC_FLAG_OUTER)
		function.SetAlias(f.Alias, false)
		switch f.Metric.Type {
		case metric.METRIC_TYPE_COUNTER:
			function.SetFillNullAsZero(true)
		case metric.METRIC_TYPE_DELAY:
			function.SetIgnoreZero(true)
		case metric.METRIC_TYPE_PERCENTAGE:
			function.SetFillNullAsZero(true)
		}
		function.Init()
		m.AddTag(function)
	}
}
