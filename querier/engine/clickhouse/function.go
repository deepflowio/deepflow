package clickhouse

import (
	"fmt"
	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse/metric"
	"metaflow/querier/engine/clickhouse/view"
	"strings"
)

type Function interface {
	Statement
	Trans(m *view.Model) view.Node
	SetAlias(alias string)
}

func GetAggFunc(name string, args []string, alias string, db string, table string) (Statement, int, error) {
	var levelFlag int
	field := args[0]
	metricStruct := metric.GetMetric(field, db, table)
	// 判断算子是否支持单层
	unlayFuns := metric.METRIC_TYPE_UNLAY_FUNCTIONS[metricStruct.Type]
	if common.IsValueInSliceString(name, unlayFuns) {
		levelFlag = view.MODEL_METRIC_LEVEL_FLAG_UNLAY
	} else {
		levelFlag = view.MODEL_METRIC_LEVEL_FLAG_LAYERED
	}
	return &AggFunction{
		Metric: metricStruct,
		Name:   name,
		Args:   args,
		Alias:  alias,
	}, levelFlag, nil
	return nil, levelFlag, nil
}

func GetBinaryFunc(name string, args []Function) (*BinaryFunction, error) {
	return &BinaryFunction{
		Name:      name,
		Functions: args,
	}, nil
}

func GetDefaultAlias(name string, args []string) string {
	alias := name
	for _, arg := range args {
		alias = fmt.Sprintf("%s_%s", alias, strings.ToLower(arg))
	}
	return alias
}

type BinaryFunction struct {
	Name      string
	Functions []Function
	Alias     string
}

func (f *BinaryFunction) Trans(m *view.Model) view.Node {
	var fields []view.Node
	for _, field := range f.Functions {
		fields = append(fields, field.Trans(m))
	}
	function := view.GetFunc(f.Name)
	function.SetFields(fields)
	function.SetFlag(view.METRIC_FLAG_OUTER)
	return function
}

func (f *BinaryFunction) Format(m *view.Model) {
	function := f.Trans(m)
	function.(view.Function).SetAlias(f.Alias, false)
	m.AddTag(function)
}

func (f *BinaryFunction) SetAlias(alias string) {
	f.Alias = alias
}

type AggFunction struct {
	// 指标量内容
	Metric *metric.Metric
	// 解析获得的参数
	Name  string
	Args  []string
	Alias string
}

func (f *AggFunction) SetAlias(alias string) {
	f.Alias = alias
}

func (f *AggFunction) FormatInnerTag(m *view.Model) (innerAlias string) {
	switch f.Metric.Type {
	case metric.METRIC_TYPE_COUNTER:
		// 内层算子使用默认alias
		innerFunction := view.DefaultFunction{
			Name:   view.FUNCTION_SUM,
			Fields: []view.Node{&view.Field{Value: f.Metric.DBField}},
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRIC_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metric.METRIC_TYPE_DELAY:
		innerFunction := view.DefaultFunction{
			Name:       view.FUNCTION_GROUP_ARRAY,
			Fields:     []view.Node{&view.Field{Value: f.Metric.DBField}},
			IgnoreZero: true,
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRIC_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metric.METRIC_TYPE_PERCENTAGE:
		innerFunction := view.DefaultFunction{
			Name:       view.FUNCTION_GROUP_ARRAY,
			Fields:     []view.Node{&view.Field{Value: f.Metric.DBField}},
			IgnoreZero: true,
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRIC_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	}
	return ""
}

func (f *AggFunction) Trans(m *view.Model) view.Node {
	outFunc := view.GetFunc(f.Name)
	outFunc.SetFlag(view.METRIC_FLAG_OUTER)
	if m.MetricLevelFlag == view.MODEL_METRIC_LEVEL_FLAG_LAYERED {
		innerAlias := f.FormatInnerTag(m)
		switch f.Metric.Type {
		case metric.METRIC_TYPE_COUNTER:
			outFunc.SetFillNullAsZero(true)
		case metric.METRIC_TYPE_DELAY:
			outFunc.SetIsGroupArray(true)
			outFunc.SetIgnoreZero(true)
		case metric.METRIC_TYPE_PERCENTAGE:
			outFunc.SetIsGroupArray(true)
			outFunc.SetFillNullAsZero(true)
		}
		outFunc.SetFields([]view.Node{&view.Field{Value: innerAlias}})
	} else if m.MetricLevelFlag == view.MODEL_METRIC_LEVEL_FLAG_UNLAY {
		switch f.Metric.Type {
		case metric.METRIC_TYPE_COUNTER:
			outFunc.SetFillNullAsZero(true)
		case metric.METRIC_TYPE_DELAY:
			outFunc.SetIgnoreZero(true)
		case metric.METRIC_TYPE_PERCENTAGE:
			outFunc.SetFillNullAsZero(true)
		}
		outFunc.SetFields([]view.Node{&view.Field{Value: f.Metric.DBField}})
	}
	outFunc.Init()
	return outFunc
}

func (f *AggFunction) Format(m *view.Model) {
	outFunc := f.Trans(m)
	outFunc.(view.Function).SetAlias(f.Alias, false)
	m.AddTag(outFunc)
}

type Field struct {
	Value string
}

func (f *Field) Trans(m *view.Model) view.Node {
	return &view.Field{Value: f.Value}
}

func (f *Field) Format(m *view.Model) {}

func (f *Field) SetAlias(alias string) {}
