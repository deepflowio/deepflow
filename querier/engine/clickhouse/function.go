package clickhouse

import (
	"fmt"
	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse/metrics"
	"metaflow/querier/engine/clickhouse/view"
	"strconv"
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
	metricStruct, ok := metrics.GetMetrics(field, db, table)
	if !ok {
		return nil, 0, nil
	}
	if _, ok := metrics.METRICS_FUNCTIONS[name]; !ok {
		return nil, 0, nil
	}
	// 判断算子是否支持单层
	unlayFuns := metrics.METRICS_TYPE_UNLAY_FUNCTIONS[metricStruct.Type]
	if common.IsValueInSliceString(name, unlayFuns) {
		levelFlag = view.MODEL_METRICS_LEVEL_FLAG_UNLAY
	} else {
		levelFlag = view.MODEL_METRICS_LEVEL_FLAG_LAYERED
	}
	return &AggFunction{
		Metrics: metricStruct,
		Name:    name,
		Args:    args,
		Alias:   alias,
	}, levelFlag, nil
	return nil, levelFlag, nil
}

func GetBinaryFunc(name string, args []Function) (*BinaryFunction, error) {
	return &BinaryFunction{
		Name:      name,
		Functions: args,
	}, nil
}

func GetFieldFunc(name string) (FieldFunction, error) {
	switch name {
	case "TimeRange":
		return &TimeRangeField{}, nil
	}
	return nil, nil
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
	function.SetFlag(view.METRICS_FLAG_OUTER)
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
	Metrics *metrics.Metrics
	// 解析获得的参数
	Name  string
	Args  []string
	Alias string
}

func (f *AggFunction) SetAlias(alias string) {
	f.Alias = alias
}

func (f *AggFunction) FormatInnerTag(m *view.Model) (innerAlias string) {
	switch f.Metrics.Type {
	case metrics.METRICS_TYPE_COUNTER, metrics.METRICS_TYPE_GAUGE:
		// 计数类和油标类，内层结构为sum
		// 内层算子使用默认alias
		innerFunction := view.DefaultFunction{
			Name:   view.FUNCTION_SUM,
			Fields: []view.Node{&view.Field{Value: f.Metrics.DBField}},
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_DELAY:
		// 时延类，内层结构为groupArray，忽略0值
		innerFunction := view.DefaultFunction{
			Name:       view.FUNCTION_GROUP_ARRAY,
			Fields:     []view.Node{&view.Field{Value: f.Metrics.DBField}},
			IgnoreZero: true,
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_PERCENTAGE, metrics.METRICS_TYPE_QUOTIENT:
		// 比例类和商值类，内层结构为sum(x)/sum(y)
		divFields := strings.Split(f.Metrics.DBField, "/")
		divField_0 := view.DefaultFunction{
			Name:   view.FUNCTION_SUM,
			Fields: []view.Node{&view.Field{Value: divFields[0]}},
		}
		divField_1 := view.DefaultFunction{
			Name:   view.FUNCTION_SUM,
			Fields: []view.Node{&view.Field{Value: divFields[1]}},
		}
		innerFunction := view.DivFunction{
			DefaultFunction: view.DefaultFunction{
				Name:   view.FUNCTION_DIV,
				Fields: []view.Node{&divField_0, &divField_1},
			},
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_TAG:
		innerAlias := fmt.Sprintf("_%s", f.Alias)
		innerFunction := view.DefaultFunction{
			Name:      view.FUNCTION_GROUP_ARRAY,
			Fields:    []view.Node{&view.Field{Value: f.Metrics.DBField}},
			Condition: f.Metrics.Condition,
			Alias:     innerAlias,
		}
		//innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	}
	return ""
}

func (f *AggFunction) Trans(m *view.Model) view.Node {
	outFunc := view.GetFunc(f.Name)
	if len(f.Args) > 1 {
		outFunc.SetArgs(f.Args[1:])
	}
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED {
		innerAlias := f.FormatInnerTag(m)
		switch f.Metrics.Type {
		case metrics.METRICS_TYPE_COUNTER, metrics.METRICS_TYPE_GAUGE:
			// 计数类和油标类，null需要补成0
			outFunc.SetFillNullAsZero(true)
		case metrics.METRICS_TYPE_DELAY, metrics.METRICS_TYPE_QUOTIENT:
			// 时延类和商值类，忽略0值
			outFunc.SetIsGroupArray(true)
			outFunc.SetIgnoreZero(true)
		case metrics.METRICS_TYPE_PERCENTAGE:
			// 比例类，null需要补成0
			outFunc.SetFillNullAsZero(true)
			outFunc.SetMath("*100")
		case metrics.METRICS_TYPE_TAG:
			outFunc.SetIsGroupArray(true)
		}
		outFunc.SetFields([]view.Node{&view.Field{Value: innerAlias}})
	} else if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_UNLAY {
		switch f.Metrics.Type {
		case metrics.METRICS_TYPE_COUNTER:
			outFunc.SetFillNullAsZero(true)
		case metrics.METRICS_TYPE_DELAY:
			outFunc.SetIgnoreZero(true)
		case metrics.METRICS_TYPE_PERCENTAGE:
			outFunc.SetFillNullAsZero(true)
		case metrics.METRICS_TYPE_TAG:
			outFunc.SetCondition(f.Metrics.Condition)
		}
		outFunc.SetFields([]view.Node{&view.Field{Value: f.Metrics.DBField}})
	}
	outFunc.SetFlag(view.METRICS_FLAG_OUTER)
	return outFunc
}

func (f *AggFunction) Format(m *view.Model) {
	outFunc := f.Trans(m)
	if f.Alias != "" {
		outFunc.(view.Function).SetAlias(f.Alias, false)
	}
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

type FieldFunction interface {
	Function
}

type TimeRangeField struct {
	FieldFunction
}

func (f *TimeRangeField) Format(m *view.Model) {}

func (f *TimeRangeField) Trans(m *view.Model) view.Node {
	var interval int
	if m.Time.Interval > 0 {
		if m.Time.DatasourceInterval > m.Time.Interval {
			interval = m.Time.DatasourceInterval
		} else {
			interval = m.Time.Interval
		}
	} else {
		interval = int(m.Time.TimeEnd - m.Time.TimeStart)
	}
	return &view.Field{Value: strconv.Itoa(interval)}
}

func (f *TimeRangeField) SetAlias(alias string) {}
