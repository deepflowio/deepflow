package clickhouse

import (
	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse/view"
)

func GetFunc(name string, args []string, math string, alias string) (Statement, int, error) {
	if len(args) > 0 {
		field := args[0]
		metric := GetMetrc(field)

		if ok := common.IsValueInSliceString(name, metric.Functions); !ok {
			// TODO: 完善error
			return nil, 0, nil
		}
		var levelFlag int
		// 判断算子是否支持单层
		if ok := common.IsValueInSliceString(name, metric.UnlayFunctions); ok {
			levelFlag = view.MODEL_METRIC_LEVEL_FLAG_UNLAY
		} else {
			levelFlag = view.MODEL_METRIC_LEVEL_FLAG_LAYERED
		}
		return &Function{
			Metric: metric,
			Name:   name,
			Args:   args,
			Math:   math,
			Alias:  alias,
		}, levelFlag, nil
	}
	return nil, 0, nil
}

type Function struct {
	// 指标量内容
	Metric *Metric
	// 解析获得的参数
	Name  string
	Args  []string
	Math  string
	Alias string
}

func (f *Function) Format(m *view.Model) {
	var outerFields []view.Node
	if m.MetricLevelFlag == view.MODEL_METRIC_LEVEL_FLAG_LAYERED {
		// 需要拆层
		for _, function := range f.Metric.InnerMetrics {
			// 内层算子使用默认alias
			innerAlias := function.SetAlias("", true)
			function.SetFlag(view.METRIC_FLAG_INNER)
			m.AddTag(function)
			// 内层算子的alias作为外层算子的fields传入
			outerFields = append(outerFields, &view.Field{Value: innerAlias})
		}
		outFunc := view.GetFunc(f.Name, f.Metric.Is0Meaningful)
		outFunc.SetFields(outerFields)
		// 标记为metric层
		outFunc.SetFlag(view.METRIC_FLAG_OUTER)
		outFunc.SetAlias(f.Alias, false)
		outFunc.SetMath(f.Math)
		m.AddTag(outFunc)
	} else if m.MetricLevelFlag == view.MODEL_METRIC_LEVEL_FLAG_UNLAY {
		// 不需要拆层
		for _, function := range f.Metric.InnerMetrics {
			innerAlias := function.SetAlias(f.Alias, false)
			function.SetMath(f.Math)
			function.SetFlag(view.METRIC_FLAG_OUTER)
			m.AddTag(function)
			outerFields = append(outerFields, &view.Field{Value: innerAlias})
		}
	}
}
