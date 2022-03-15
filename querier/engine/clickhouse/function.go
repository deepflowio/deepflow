package clickhouse

import (
	"fmt"
	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse/metric"
	"metaflow/querier/engine/clickhouse/view"
	"strings"
)

func GetFunc(name string, args []string, math string, alias string, db string, table string) (Statement, int, error) {
	if len(args) > 0 {
		field := args[0]
		metric := metric.GetMetric(field, db, table)
		var levelFlag int
		// 判断算子是否支持单层
		unlayFuns := view.METRIC_TYPE_UNLAY_FUNCTIONS[metric.Type]
		if common.IsValueInSliceString(name, unlayFuns) {
			levelFlag = view.MODEL_METRIC_LEVEL_FLAG_UNLAY
		} else {
			levelFlag = view.MODEL_METRIC_LEVEL_FLAG_LAYERED
		}
		if alias == "" {
			alias = GetDefaultAlias(name, args, math)
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

func GetDefaultAlias(name string, args []string, math string) string {
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
	Args  []string
	Math  string
	Alias string
}

func (f *Function) Format(m *view.Model) {
	if m.MetricLevelFlag == view.MODEL_METRIC_LEVEL_FLAG_LAYERED {
		// 需要拆层
		var outerFields []view.Node
		isGroupArray := false

		for _, function := range f.Metric.InnerMetrics {
			// 内层算子使用默认alias
			innerAlias := function.SetAlias("", true)
			function.SetFlag(view.METRIC_FLAG_INNER)
			function.SetIs0Meaningful(f.Metric.Is0Meaningful)
			function.Init()
			m.AddTag(function)
			// 判断内层算子是否为GroupArray
			if function.GetName() == view.FUNCTION_GROUP_ARRAY {
				isGroupArray = true
			}
			// 内层算子的alias作为外层算子的fields传入
			outerFields = append(outerFields, &view.Field{Value: innerAlias})
		}
		outFunc := view.GetFunc(f.Name, f.Metric.Is0Meaningful)
		outFunc.SetFields(outerFields)
		// 标记为metric层
		outFunc.SetFlag(view.METRIC_FLAG_OUTER)
		outFunc.SetAlias(f.Alias, false)
		outFunc.SetMath(f.Math)
		outFunc.SetIsGroupArray(isGroupArray)
		// 当Is0Meaningful为False时，算子会携带If (例：SUMIf(rtt, rtt>0))
		// 内层是数组的情况下，外层算子（例：SUMArray）不支持携带If。
		// 在内层就将0值限制（例：groupArrayIf(rtt, rtt>0)）
		if isGroupArray {
			outFunc.SetIs0Meaningful(view.METRIC_IS_0_MEANINGFUL_TRUE)
		} else {
			outFunc.SetIs0Meaningful(f.Metric.Is0Meaningful)
		}
		outFunc.Init()
		m.AddTag(outFunc)
	} else if m.MetricLevelFlag == view.MODEL_METRIC_LEVEL_FLAG_UNLAY {
		// 不需要拆层
		function := view.GetFunc(f.Name, f.Metric.Is0Meaningful)
		function.SetFields([]view.Node{&view.Field{Value: f.Metric.DBField}})
		function.SetFlag(view.METRIC_FLAG_OUTER)
		function.SetAlias(f.Alias, false)
		function.SetMath(f.Math)
		function.SetIs0Meaningful(f.Metric.Is0Meaningful)
		function.Init()
		m.AddTag(function)
	}
}
