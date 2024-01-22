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

package view

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/common"
)

const (
	FUNCTION_SUM         = "Sum"
	FUNCTION_MAX         = "Max"
	FUNCTION_MIN         = "Min"
	FUNCTION_AVG         = "Avg"
	FUNCTION_COUNTER_AVG = "Counter_Avg"
	FUNCTION_DELAY_AVG   = "Delay_Avg"
	FUNCTION_AAVG        = "AAvg"
	FUNCTION_PCTL        = "Percentile"
	FUNCTION_PCTL_EXACT  = "PercentileExact"
	FUNCTION_STDDEV      = "Stddev"
	FUNCTION_SPREAD      = "Spread"
	FUNCTION_RSPREAD     = "Rspread"
	FUNCTION_APDEX       = "Apdex"
	FUNCTION_GROUP_ARRAY = "groupArray"
	FUNCTION_DIV         = "/"
	FUNCTION_PLUS        = "+"
	FUNCTION_MINUS       = "-"
	FUNCTION_MULTIPLY    = "*"
	FUNCTION_COUNT       = "Count"
	FUNCTION_UNIQ        = "Uniq"
	FUNCTION_UNIQ_EXACT  = "UniqExact"
	FUNCTION_PERSECOND   = "PerSecond"
	FUNCTION_PERCENTAG   = "Percentage"
	FUNCTION_HISTOGRAM   = "Histogram"
	FUNCTION_LAST        = "Last"
	FUNCTION_TOPK        = "TopK"
	FUNCTION_ANY         = "Any"
	FUNCTION_DERIVATIVE  = "nonNegativeDerivative"
)

// 对外提供的算子与数据库实际算子转换
var FUNC_NAME_MAP map[string]string = map[string]string{
	FUNCTION_SUM:         "SUM",
	FUNCTION_MAX:         "MAX",
	FUNCTION_MIN:         "MIN",
	FUNCTION_AAVG:        "AVG",
	FUNCTION_PCTL:        "quantile",
	FUNCTION_PCTL_EXACT:  "quantileExact",
	FUNCTION_STDDEV:      "stddevPopStable",
	FUNCTION_GROUP_ARRAY: "groupArray",
	FUNCTION_PLUS:        "plus",
	FUNCTION_DIV:         "Div",
	FUNCTION_MINUS:       "minus",
	FUNCTION_MULTIPLY:    "multiply",
	FUNCTION_COUNT:       "COUNT",
	FUNCTION_UNIQ:        "uniq",
	FUNCTION_UNIQ_EXACT:  "uniqExact",
	FUNCTION_LAST:        "last_value",
	FUNCTION_TOPK:        "topK",
	FUNCTION_ANY:         "any", // because need to set any to topK(1), and '(1)' may be appended after 'If' in func (f *DefaultFunction) WriteTo(buf *bytes.Buffer)
	FUNCTION_DERIVATIVE:  "nonNegativeDerivative",
}

var MATH_FUNCTIONS = []string{
	FUNCTION_DIV, FUNCTION_PLUS, FUNCTION_MINUS, FUNCTION_MULTIPLY,
	FUNCTION_PERCENTAG, FUNCTION_PERSECOND, FUNCTION_HISTOGRAM,
}

func GetFunc(name string) Function {
	switch name {
	case FUNCTION_SPREAD:
		return &SpreadFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_RSPREAD:
		return &RspreadFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_APDEX:
		return &ApdexFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_DIV:
		return &DivFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_MIN:
		return &MinFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_PERCENTAG:
		return &PercentageFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_PERSECOND:
		return &PerSecondFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_HISTOGRAM:
		return &HistogramFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_COUNTER_AVG:
		return &CounterAvgFunction{DefaultFunction: DefaultFunction{Name: FUNC_NAME_MAP[FUNCTION_AAVG]}}
	case FUNCTION_DELAY_AVG:
		return &DelayAvgFunction{DefaultFunction: DefaultFunction{Name: FUNC_NAME_MAP[FUNCTION_AAVG]}}
	case FUNCTION_DERIVATIVE:
		return &NonNegativeDerivativeFunction{DefaultFunction: DefaultFunction{Name: name}}
	default:
		return &DefaultFunction{Name: name}
	}
	return nil
}

type Function interface {
	Node
	SetFields([]Node)
	SetArgs([]string)
	SetFlag(int)
	SetAlias(string, bool) string
	GetDefaultAlias(bool) string
	SetIgnoreZero(bool)
	SetFillNullAsZero(bool)
	SetIsGroupArray(bool)
	SetCondition(string)
	SetTime(*Time)
	SetMath(string)
	GetFlag() int
	GetName() string
	GetFields() []Node
	Init()
}

func FormatField(field string) string {
	/* 	field = strings.ReplaceAll(field, "'", "")
	   	field = strings.ReplaceAll(field, "+", "_plus_")
	   	field = strings.ReplaceAll(field, "-", "_minus_")
	   	field = strings.ReplaceAll(field, "*", "_multiply_")
	   	field = strings.ReplaceAll(field, "/", "_div_")
	   	field = strings.ReplaceAll(field, "(", "_")
	   	field = strings.ReplaceAll(field, ")", "_")
	   	field = strings.ReplaceAll(field, "[", "_")
	   	field = strings.ReplaceAll(field, "]", "_")
	   	field = strings.ReplaceAll(field, ",", "_")
	   	field = strings.ReplaceAll(field, " ", "_")
	   	field = strings.ReplaceAll(field, "<", "_")
	   	field = strings.ReplaceAll(field, ">", "_")
	   	field = strings.ReplaceAll(field, "=", "_")
	   	field = strings.ReplaceAll(field, "!", "_")
	   	field = strings.ReplaceAll(field, ".", "_") */
	field = strings.ReplaceAll(field, "`", "")
	return field
}

type DefaultFunction struct {
	Name           string   // 算子名称
	Fields         []Node   // 指标量名称
	Args           []string // 其他参数
	DerivativeArgs []string // Derivative其他参数
	Alias          string   // as
	Condition      string   // 算子过滤 例：Condition："code in [1,2]" SUMIf(byte, code in [1,2])
	Withs          []Node
	Flag           int
	IgnoreZero     bool
	FillNullAsZero bool
	IsGroupArray   bool // 是否针对list做聚合，例:SUMArray(rtt_max)
	Nest           bool // 是否为内层嵌套算子
	Time           *Time
	Math           string
	NodeBase
}

func (f *DefaultFunction) Init() {
	for _, field := range f.Fields {
		switch function := field.(type) {
		case Function:
			function.SetTime(f.Time)
			function.Init()
		}
	}
}

func (f *DefaultFunction) GetFields() []Node {
	return f.Fields
}

func (f *DefaultFunction) GetFlag() int {
	return f.Flag
}

func (f *DefaultFunction) GetName() string {
	return f.Name
}

func (f *DefaultFunction) GetWiths() []Node {
	for _, field := range f.Fields {
		f.Withs = append(f.Withs, field.GetWiths()...)
	}
	return f.Withs
}

func (f *DefaultFunction) ToString() string {
	buf := bytes.Buffer{}
	f.WriteTo(&buf)
	return buf.String()
}

func (f *DefaultFunction) WriteTo(buf *bytes.Buffer) {
	dbFuncName, ok := FUNC_NAME_MAP[f.Name]
	if !ok {
		dbFuncName = f.Name
	}
	// derivative
	if f.Name == FUNCTION_DERIVATIVE {
		partitionBy := ""
		argsNoSuffixStr := ""
		argsNoSuffix := []string{}
		if len(f.DerivativeArgs) > 0 {
			for _, arg := range f.DerivativeArgs {
				arg = strings.Trim(arg, "`")
				argsNoSuffix = append(argsNoSuffix, arg)
			}
			argsNoSuffixStr = strings.Join(argsNoSuffix, "_")
			if len(f.DerivativeArgs) > 1 {
				partitionBy = fmt.Sprintf("PARTITION BY %s ", strings.Join(f.DerivativeArgs[1:], ","))
			}
		}
		buf.WriteString(fmt.Sprintf("nonNegativeDerivative(last_value(%s),_time) OVER (%sORDER BY _time)", f.DerivativeArgs[0], partitionBy))
		if f.Alias != "" {
			buf.WriteString(" AS ")
			buf.WriteString("`")
			buf.WriteString(fmt.Sprintf("_nonnegativederivative_%s", argsNoSuffixStr))
			buf.WriteString("`")
		}
		return
	}

	isSingleTagTok := f.Name == FUNCTION_TOPK && len(f.Args) == 1
	if isSingleTagTok {
		buf.WriteString("arrayStringConcat(")
	}
	buf.WriteString(dbFuncName)

	if f.IsGroupArray {
		buf.WriteString("Array")
	}

	// 有过滤条件或者忽略0值(Array后缀算子不支持携带If)
	if (f.Condition != "" || f.IgnoreZero) && !f.IsGroupArray {
		buf.WriteString("If")
	}

	args := f.Args
	if f.Name == FUNCTION_TOPK {
		args = f.Args[len(f.Args)-1:]
	} else if f.Name == FUNCTION_ANY {
		args = nil
	}
	if len(args) > 0 {
		buf.WriteString("(")
		for i, arg := range args {
			buf.WriteString(arg)
			if i < len(args)-1 {
				buf.WriteString(", ")
			}
		}
		buf.WriteString(")")
	}

	buf.WriteString("(")

	if !f.IsGroupArray {
		for i, field := range f.Fields {
			field.WriteTo(buf)
			if i < len(f.Fields)-1 || f.Condition != "" || f.IgnoreZero {
				buf.WriteString(", ")
			}
		}
		if f.Condition != "" {
			buf.WriteString(f.Condition)
		}
		if f.IgnoreZero {
			if f.Condition != "" {
				buf.WriteString(" AND ")
			}
			for i, field := range f.Fields {
				field.WriteTo(buf)
				buf.WriteString(" > 0")
				if i < len(f.Fields)-1 {
					buf.WriteString(" AND ")
				}
			}
		}
	} else {
		// Array后缀的算子处理0值无意义指标量：MAXArray(arrayFilter(x->x>0), _array)
		for i, field := range f.Fields {
			if !f.IgnoreZero {
				field.WriteTo(buf)
			} else {
				buf.WriteString("arrayFilter(x -> x>0, ")
				field.WriteTo(buf)
				buf.WriteString(")")
			}

			if i < len(f.Fields)-1 {
				buf.WriteString(", ")
			}
		}
	}

	buf.WriteString(")")
	if isSingleTagTok {
		buf.WriteString(", ',')")
	}
	buf.WriteString(f.Math)
	if !f.Nest && f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}

}

func (f *DefaultFunction) GetDefaultAlias(inner bool) string {
	if f.Nest && f.Alias != "" {
		return f.Alias
	}
	buf := bytes.Buffer{}
	if inner {
		buf.WriteString("_")
	}
	if funcName, ok := FUNC_NAME_MAP[f.Name]; ok {
		buf.WriteString(strings.ToLower(funcName))
	} else {
		buf.WriteString(strings.ToLower(f.Name))
	}
	buf.WriteString("_")
	for i, field := range f.Fields {
		var fieldStr string
		switch f := field.(type) {
		case *Field:
			fieldStr = FormatField(f.ToString())
		case Function:
			fieldStr = f.GetDefaultAlias(inner)
		}
		buf.WriteString(strings.ReplaceAll(fieldStr, "'", ""))
		if i < len(f.Fields)-1 {
			buf.WriteString("_")
		}
	}

	for _, arg := range f.Args {
		buf.WriteString("_")
		buf.WriteString(FormatField(arg))
	}
	if f.Condition != "" {
		buf.WriteString("_")
		buf.WriteString(FormatField(f.Condition))
	}
	return buf.String()
}

func (f *DefaultFunction) SetAlias(alias string, inner bool) string {
	if alias == "" {
		alias = f.GetDefaultAlias(inner)
	}
	alias = "`" + strings.Trim(alias, "`") + "`"
	f.Alias = alias

	return alias
}

func (f *DefaultFunction) SetTime(time *Time) {
	f.Time = time
}

func (f *DefaultFunction) SetFields(fields []Node) {
	f.Fields = fields
}

func (f *DefaultFunction) SetFlag(flag int) {
	f.Flag = flag
}

func (f *DefaultFunction) SetArgs(args []string) {
	f.Args = args
}

func (f *DefaultFunction) SetIgnoreZero(ignoreZero bool) {
	f.IgnoreZero = ignoreZero
}

func (f *DefaultFunction) SetFillNullAsZero(fillNullAsZero bool) {
	f.FillNullAsZero = fillNullAsZero
}

func (f *DefaultFunction) SetIsGroupArray(isGroupArray bool) {
	f.IsGroupArray = isGroupArray
}

func (f *DefaultFunction) SetCondition(condition string) {
	f.Condition = condition
}

func (f *DefaultFunction) SetMath(math string) {
	f.Math = math
}

type Field struct {
	DefaultFunction
	Value string
	Withs []Node
}

func (f *Field) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(f.Value)
}

func (f *Field) GetWiths() []Node {
	return f.Withs
}

func (f *Field) ToString() string {
	return f.Value
}

func (f *Field) GetDefaultAlias(inner bool) string {
	return f.Value
}

type SpreadFunction struct {
	DefaultFunction
	minusFunction *DefaultFunction
}

func (f *SpreadFunction) Init() {
	maxFunc := DefaultFunction{
		Name:         FUNCTION_MAX,
		Fields:       f.Fields,
		IgnoreZero:   f.IgnoreZero,
		Nest:         true,
		IsGroupArray: f.IsGroupArray,
		Condition:    f.Condition,
	}
	minFunc := MinFunction{
		DefaultFunction: DefaultFunction{
			Name:           FUNCTION_MIN,
			Fields:         f.Fields,
			IgnoreZero:     f.IgnoreZero,
			Nest:           true,
			FillNullAsZero: f.FillNullAsZero,
			Time:           f.Time,
			IsGroupArray:   f.IsGroupArray,
			Condition:      f.Condition,
		},
	}
	f.minusFunction = &DefaultFunction{
		Name:   FUNCTION_MINUS,
		Fields: []Node{&maxFunc, &minFunc},
		Math:   f.Math,
	}
}

func (f *SpreadFunction) WriteTo(buf *bytes.Buffer) {
	f.minusFunction.WriteTo(buf)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}
}

func (f *SpreadFunction) GetWiths() []Node {
	f.Withs = append(f.Withs, f.minusFunction.GetWiths()...)
	return f.Withs
}

type RspreadFunction struct {
	DefaultFunction
	divFunction *DivFunction // rspread的实际算子是div
}

func (f *RspreadFunction) Init() {
	maxFunc := DefaultFunction{
		Name:         FUNCTION_MAX,
		Fields:       f.Fields,
		IgnoreZero:   f.IgnoreZero,
		Nest:         true,
		IsGroupArray: f.IsGroupArray,
		Condition:    f.Condition,
	}
	minFunc := MinFunction{
		DefaultFunction: DefaultFunction{
			Name:           FUNCTION_MIN,
			Fields:         f.Fields,
			IgnoreZero:     f.IgnoreZero,
			Nest:           true,
			FillNullAsZero: f.FillNullAsZero,
			Time:           f.Time,
			IsGroupArray:   f.IsGroupArray,
			Condition:      f.Condition,
		},
	}
	f.divFunction = &DivFunction{
		DivType: FUNCTION_DIV_TYPE_FILL_MINIMUM,
		DefaultFunction: DefaultFunction{
			Name:   FUNCTION_DIV,
			Fields: []Node{&maxFunc, &minFunc},
			Math:   f.Math,
		},
	}
}

func (f *RspreadFunction) WriteTo(buf *bytes.Buffer) {
	f.divFunction.WriteTo(buf)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}
}

func (f *RspreadFunction) GetWiths() []Node {
	return f.divFunction.GetWiths()
}

type PercentageFunction struct {
	DefaultFunction
	divFunction *DivFunction
}

func (f *PercentageFunction) Init() {
	if len(f.Fields) < 2 {
		f.Fields = append(f.Fields, &Field{Value: "1"})
	}
	f.divFunction = &DivFunction{
		DefaultFunction: DefaultFunction{
			Name:   FUNCTION_DIV,
			Fields: f.Fields,
			Math:   "*100",
		},
	}
}

func (f *PercentageFunction) WriteTo(buf *bytes.Buffer) {
	f.divFunction.WriteTo(buf)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}
}

func (f *PercentageFunction) GetWiths() []Node {
	return f.divFunction.GetWiths()
}

type HistogramFunction struct {
	DefaultFunction
}

func (f *HistogramFunction) WriteTo(buf *bytes.Buffer) {
	buf.WriteString("histogramIf(")
	buf.WriteString(FormatField(f.Fields[1].ToString()))
	buf.WriteString(")(")
	buf.WriteString(f.Fields[0].ToString())
	buf.WriteString(fmt.Sprintf(",%s>0)", f.Fields[0].ToString()))
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}
}

type PerSecondFunction struct {
	DefaultFunction
	divFunction *DivFunction
}

func (f *PerSecondFunction) Init() {
	var interval int
	var aggFuncName string
	argFunc := f.Fields[0].(Function)
	// 获取聚合算子
	for {
		if common.IsValueInSliceString(argFunc.GetName(), MATH_FUNCTIONS) {
			innerFunc, ok := argFunc.GetFields()[0].(Function)
			if !ok {
				break
			}
			argFunc = innerFunc
			continue
		} else {
			aggFuncName = argFunc.GetName()
			break
		}
	}
	if aggFuncName == FUNCTION_SUM || aggFuncName == FUNCTION_UNIQ_EXACT || aggFuncName == FUNCTION_UNIQ || aggFuncName == FUNCTION_COUNT {
		if f.Time.Interval > 0 {
			if f.Time.DatasourceInterval > f.Time.Interval {
				interval = f.Time.DatasourceInterval
			} else {
				interval = f.Time.Interval
			}
		} else {
			interval = int(f.Time.TimeEnd - f.Time.TimeStart)
		}
	} else {
		interval = f.Time.DatasourceInterval
	}
	if interval <= 0 {
		interval = f.Time.DatasourceInterval
	}
	interval = interval * f.Time.WindowSize
	f.Fields = append(f.Fields, &Field{Value: strconv.Itoa(interval)})
	f.divFunction = &DivFunction{
		DefaultFunction: DefaultFunction{
			Name:   FUNCTION_DIV,
			Fields: f.Fields,
		},
	}
}

func (f *PerSecondFunction) WriteTo(buf *bytes.Buffer) {
	f.divFunction.WriteTo(buf)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}
}

func (f *PerSecondFunction) GetWiths() []Node {
	return f.divFunction.GetWiths()
}

type ApdexFunction struct {
	DefaultFunction
	divFunction *DivFunction // apdex的实际算子是div
}

func (f *ApdexFunction) Init() {
	if f.IsGroupArray {
		// (count(arrayFilter(x -> (x <= arg), _grouparray_rtt)) + count(arrayFilter(x -> ((arg < x) AND (x <= (arg * 4))), _grouparray_rtt))/2) / countArray(_grouparray_rtt)
		satisfy := fmt.Sprintf(
			"arrayFilter(x -> (x <= %s AND 0 < x), %s)",
			f.Args[0], f.Fields[0].ToString(),
		)
		toler := fmt.Sprintf(
			"arrayFilter(x -> ((%s < x) AND (x <= (%s * 4))), %s)",
			f.Args[0], f.Args[0], f.Fields[0].ToString(),
		)
		// count(arrayFilter(x -> (x <= arg), _grouparray_rtt))
		countSatisfyAlias := FormatField(fmt.Sprintf("apdex_satisfy_%s_%s", f.Fields[0].ToString(), f.Args[0]))
		countSatisfy := DefaultFunction{
			Name:         FUNCTION_COUNT,
			Fields:       []Node{&Field{Value: satisfy}},
			Alias:        countSatisfyAlias,
			Nest:         true,
			IsGroupArray: true,
		}
		// count(arrayFilter(x -> ((arg < x) AND (x <= (arg * 4))), _grouparray_rtt))
		countToler := DefaultFunction{
			Name:         FUNCTION_COUNT,
			Fields:       []Node{&Field{Value: toler}},
			Nest:         true,
			IsGroupArray: true,
		}
		// countToler / 2
		divTolerAlias := FormatField(fmt.Sprintf("apdex_toler_%s_%s", f.Fields[0].ToString(), f.Args[0]))
		divToler := DivFunction{
			DefaultFunction: DefaultFunction{
				Name:   FUNCTION_DIV,
				Fields: []Node{&countToler, &Field{Value: "2"}},
				Alias:  divTolerAlias,
				Nest:   true,
			},
			DivType: FUNCTION_DIV_TYPE_DEFAULT,
		}
		plus := DefaultFunction{
			Name:   FUNCTION_PLUS,
			Fields: []Node{&countSatisfy, &divToler},
			Nest:   true,
		}
		// countArray(arrayFilter(x -> (x != 0), _grouparray_rtt))
		count := DefaultFunction{
			Name:         FUNCTION_COUNT,
			Fields:       []Node{&Field{Value: f.Fields[0].ToString()}},
			IsGroupArray: true,
			IgnoreZero:   true,
		}
		f.divFunction = &DivFunction{
			DefaultFunction: DefaultFunction{
				Name:   FUNCTION_DIV,
				Fields: []Node{&plus, &count},
				Math:   "*100",
			},
			// count为0则结果为null
			DivType: FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL,
		}
	} else {
		// (sum(if(rtt<=arg,1,0))+sum(if(arg<rtt and rtt<=arg*4, 0.5, 0)))/count()
		satisfy := fmt.Sprintf("if(%s<=%s,1,0)", f.Fields[0].ToString(), f.Args[0])
		toler := fmt.Sprintf(
			"if(%s<%s AND %s<=%s*4,0.5,0)",
			f.Args[0], f.Fields[0].ToString(), f.Fields[0].ToString(), f.Args[0],
		)
		sumSatisfyAlias := FormatField(fmt.Sprintf("apdex_satisfy_%s_%s", f.Fields[0].ToString(), f.Args[0]))
		sumSatisfy := DefaultFunction{
			Name:   FUNCTION_SUM,
			Fields: []Node{&Field{Value: satisfy}},
			Alias:  sumSatisfyAlias,
			Nest:   true,
		}
		sumTolerAlias := FormatField(fmt.Sprintf("apdex_toler_%s_%s", f.Fields[0].ToString(), f.Args[0]))
		sumToler := DefaultFunction{
			Name:   FUNCTION_SUM,
			Fields: []Node{&Field{Value: toler}},
			Alias:  sumTolerAlias,
			Nest:   true,
		}
		plus := DefaultFunction{
			Name:   FUNCTION_PLUS,
			Fields: []Node{&sumSatisfy, &sumToler},
			Nest:   true,
		}
		count := DefaultFunction{
			Name: FUNCTION_COUNT,
		}
		f.divFunction = &DivFunction{
			DefaultFunction: DefaultFunction{
				Name:   FUNCTION_DIV,
				Fields: []Node{&plus, &count},
				Math:   "*100",
			},
			// count为0则结果为null
			DivType: FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL,
		}
	}

}

func (f *ApdexFunction) WriteTo(buf *bytes.Buffer) {
	f.divFunction.WriteTo(buf)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}
}

func (f *ApdexFunction) GetWiths() []Node {
	return f.divFunction.GetWiths()
}

type DivFunction struct {
	DefaultFunction
	DivType int
}

func (f *DivFunction) WriteTo(buf *bytes.Buffer) {
	if f.DivType == FUNCTION_DIV_TYPE_DEFAULT {
		buf.WriteString("divide(")
		f.Fields[0].WriteTo(buf)
		buf.WriteString(", ")
		f.Fields[1].WriteTo(buf)
		buf.WriteString(")")
	} else if f.DivType == FUNCTION_DIV_TYPE_FILL_MINIMUM {
		buf.WriteString("divide(")
		f.Fields[0].WriteTo(buf)
		buf.WriteString("+1e-15, ")
		f.Fields[1].WriteTo(buf)
		buf.WriteString("+1e-15)")
	} else if f.DivType == FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL {
		buf.WriteString("`divide_0diveider_as_null")
		buf.WriteString(FormatField(f.Fields[0].(Function).GetDefaultAlias(true)))
		buf.WriteString(FormatField(f.Fields[1].(Function).GetDefaultAlias(true)))
		buf.WriteString("`")
	} else if f.DivType == FUNCTION_DIV_TYPE_0DIVIDER_AS_0 {
		buf.WriteString("`divide_0diveider_as_0")
		buf.WriteString(FormatField(f.Fields[0].(Function).GetDefaultAlias(true)))
		buf.WriteString(FormatField(f.Fields[1].(Function).GetDefaultAlias(true)))
		buf.WriteString("`")
	}
	buf.WriteString(f.Math)
	if !f.Nest && f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}
}

func (f *DivFunction) GetWiths() []Node {
	f.Withs = append(f.Withs, f.Fields[0].GetWiths()...)
	f.Withs = append(f.Withs, f.Fields[1].GetWiths()...)
	if f.DivType == FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL {
		with := fmt.Sprintf(
			"if(%s>0, divide(%s, %s), null)",
			f.Fields[1].ToString(), f.Fields[0].ToString(), f.Fields[1].ToString(),
		)
		alias := FormatField(fmt.Sprintf(
			"divide_0diveider_as_null%s%s",
			FormatField(f.Fields[0].(Function).GetDefaultAlias(true)),
			FormatField(f.Fields[1].(Function).GetDefaultAlias(true)),
		))
		f.Withs = append(f.Withs, &With{Value: with, Alias: alias})
	} else if f.DivType == FUNCTION_DIV_TYPE_0DIVIDER_AS_0 {
		with := fmt.Sprintf(
			"if(%s>0, divide(%s, %s), 0)",
			f.Fields[1].ToString(), f.Fields[0].ToString(), f.Fields[1].ToString(),
		)
		alias := FormatField(fmt.Sprintf(
			"divide_0diveider_as_0%s%s",
			FormatField(f.Fields[0].(Function).GetDefaultAlias(true)),
			FormatField(f.Fields[1].(Function).GetDefaultAlias(true)),
		))
		f.Withs = append(f.Withs, &With{Value: with, Alias: alias})
	}
	return f.Withs
}

type MinFunction struct {
	DefaultFunction
}

func (f *MinFunction) WriteTo(buf *bytes.Buffer) {
	if !f.FillNullAsZero {
		f.DefaultFunction.WriteTo(buf)
	} else {
		buf.WriteString("`")
		buf.WriteString("min_fillnullaszero_")
		buf.WriteString(FormatField(f.Fields[0].ToString()))
		buf.WriteString("`")
		buf.WriteString(f.Math)
		if f.Alias != "" {
			buf.WriteString(" AS ")
			buf.WriteString("`")
			buf.WriteString(strings.Trim(f.Alias, "`"))
			buf.WriteString("`")
		}
	}
}

func (f *MinFunction) GetWiths() []Node {
	if !f.FillNullAsZero {
		return f.DefaultFunction.GetWiths()
	} else {
		var count int
		if f.Time.Interval > 0 {
			count = f.Time.WindowSize * f.Time.Interval / f.Time.DatasourceInterval
		} else {
			count = int(f.Time.TimeEnd-f.Time.TimeStart)/f.Time.DatasourceInterval + 1
		}
		with := fmt.Sprintf(
			"if(count(%s)=%d, min(%s), 0)",
			f.Fields[0].ToString(), count, f.Fields[0].ToString(),
		)
		alias := FormatField(fmt.Sprintf(
			"min_fillnullaszero_%s", f.Fields[0].ToString(),
		))
		f.Withs = append(f.Withs, &With{Value: with, Alias: alias})
		return f.Withs
	}
}

type CounterAvgFunction struct {
	DefaultFunction
}

func (f *CounterAvgFunction) WriteTo(buf *bytes.Buffer) {
	var interval int
	if f.Time.Interval > 0 {
		interval = f.Time.Interval
	} else {
		interval = int(f.Time.TimeEnd-f.Time.TimeStart) + f.Time.DatasourceInterval
	}
	buf.WriteString(fmt.Sprintf("sum(%s)/(%d/%d)", f.Fields[0].ToString(), interval, f.Time.DatasourceInterval))
	buf.WriteString(f.Math)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(f.Alias, "`"))
		buf.WriteString("`")
	}
}

type DelayAvgFunction struct {
	DefaultFunction
	divFunction *DivFunction
}

func (f *DelayAvgFunction) Init() {
	// Sum(Numerator)/Sum(Denominator)
	if strings.Contains(f.Fields[0].ToString(), "/") {
		fieldsSlice := strings.Split(f.Fields[0].ToString(), "/")
		if len(fieldsSlice) > 1 {
			dividendSumFunc := DefaultFunction{
				Name:   FUNCTION_SUM,
				Fields: []Node{&Field{Value: fieldsSlice[0]}},
				Nest:   true,
			}
			divisorSumFunc := DefaultFunction{
				Name:      FUNCTION_SUM,
				Fields:    []Node{&Field{Value: fieldsSlice[1]}},
				Nest:      true,
				Condition: fmt.Sprintf("%s>0", fieldsSlice[1]),
			}
			f.divFunction = &DivFunction{
				DivType: FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL,
				DefaultFunction: DefaultFunction{
					Name:   FUNCTION_DIV,
					Fields: []Node{&dividendSumFunc, &divisorSumFunc},
					Math:   f.Math,
				},
			}
		}
	}
}

func (f *DelayAvgFunction) WriteTo(buf *bytes.Buffer) {
	if !strings.Contains(f.Fields[0].ToString(), "/") {
		f.DefaultFunction.WriteTo(buf)
	} else {
		f.divFunction.WriteTo(buf)
		if f.Alias != "" {
			buf.WriteString(" AS ")
			buf.WriteString("`")
			buf.WriteString(strings.Trim(f.Alias, "`"))
			buf.WriteString("`")
		}
	}
}

func (f *DelayAvgFunction) GetWiths() []Node {
	if !strings.Contains(f.Fields[0].ToString(), "/") {
		return f.DefaultFunction.GetWiths()
	} else {
		return f.divFunction.GetWiths()
	}
}

type NonNegativeDerivativeFunction struct {
	DefaultFunction
}

func (f *NonNegativeDerivativeFunction) WriteTo(buf *bytes.Buffer) {
	partitionBy := ""
	argsNoSuffixStr := ""
	argsNoSuffix := []string{}
	if len(f.DerivativeArgs) > 0 {
		for _, arg := range f.DerivativeArgs {
			arg = strings.Trim(arg, "`")
			argsNoSuffix = append(argsNoSuffix, arg)
		}
		argsNoSuffixStr = strings.Join(argsNoSuffix, "_")
		if len(f.DerivativeArgs) > 1 {
			partitionBy = fmt.Sprintf("PARTITION BY %s ", strings.Join(f.DerivativeArgs[1:], ","))
		}
	}
	buf.WriteString(fmt.Sprintf("nonNegativeDerivative(last_value(%s),_time) OVER (%sORDER BY _time)", f.DerivativeArgs[0], partitionBy))
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(fmt.Sprintf("_nonnegativederivative_%s", argsNoSuffixStr))
		buf.WriteString("`")
	}
}
