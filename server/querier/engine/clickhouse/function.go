/*
 * Copyright (c) 2023 Yunshan Networks
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

package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

const (
	TAG_FUNCTION_NODE_TYPE                  = "node_type"
	TAG_FUNCTION_ICON_ID                    = "icon_id"
	TAG_FUNCTION_MASK                       = "mask"
	TAG_FUNCTION_TIME                       = "time"
	TAG_FUNCTION_TO_UNIX_TIMESTAMP_64_MICRO = "toUnixTimestamp64Micro"
	TAG_FUNCTION_TO_UNIX_TIMESTAMP          = "toUnixTimestamp"
	TAG_FUNCTION_TO_STRING                  = "toString"
	TAG_FUNCTION_IF                         = "if"
	TAG_FUNCTION_UNIQ                       = "uniq"
	TAG_FUNCTION_ANY                        = "any"
	TAG_FUNCTION_TOPK                       = "topK"
	TAG_FUNCTION_NEW_TAG                    = "newTag"
	TAG_FUNCTION_ENUM                       = "enum"
	TAG_FUNCTION_FAST_FILTER                = "FastFilter"
)

const INTERVAL_1D = 86400

var TAG_FUNCTIONS = []string{
	TAG_FUNCTION_NODE_TYPE, TAG_FUNCTION_ICON_ID, TAG_FUNCTION_MASK, TAG_FUNCTION_TIME,
	TAG_FUNCTION_TO_UNIX_TIMESTAMP_64_MICRO, TAG_FUNCTION_TO_STRING, TAG_FUNCTION_IF,
	TAG_FUNCTION_UNIQ, TAG_FUNCTION_ANY, TAG_FUNCTION_TOPK, TAG_FUNCTION_TO_UNIX_TIMESTAMP,
	TAG_FUNCTION_NEW_TAG, TAG_FUNCTION_ENUM, TAG_FUNCTION_FAST_FILTER,
}

type Function interface {
	Statement
	Trans(m *view.Model) view.Node
	SetAlias(alias string)
}

func GetTagFunction(name string, args []string, alias, db, table string) (Statement, error) {
	if !common.IsValueInSliceString(name, TAG_FUNCTIONS) {
		return nil, nil
	}
	switch name {
	case "time":
		time := Time{Args: args, Alias: alias}
		return &time, nil
	default:
		tagFunction := TagFunction{Name: name, Args: args, Alias: alias, DB: db, Table: table}
		err := tagFunction.Check()
		return &tagFunction, err
	}
}

func GetAggFunc(name string, args []string, alias string, db string, table string, ctx context.Context, isDerivative bool, derivativeGroupBy []string) (Statement, int, string, error) {
	if name == view.FUNCTION_TOPK || name == view.FUNCTION_ANY {
		return GetTopKTrans(name, args, alias, db, table, ctx)
	}

	var levelFlag int
	field := args[0]
	field = strings.Trim(field, "`")

	if name == view.FUNCTION_COUNT && field != metrics.COUNT_METRICS_NAME {
		return nil, 0, "", fmt.Errorf("function [%s] not support metric [%s]",
			view.FUNCTION_COUNT, metrics.COUNT_METRICS_NAME)
	}

	function, ok := metrics.METRICS_FUNCTIONS_MAP[name]
	if !ok {
		return nil, 0, "", nil
	}
	metricStruct, ok := metrics.GetAggMetrics(field, db, table, ctx)
	if !ok {
		return nil, 0, "", nil
	}
	if metricStruct.Type == metrics.METRICS_TYPE_ARRAY {
		return nil, 0, "", nil
	}
	unit := strings.ReplaceAll(function.UnitOverwrite, "$unit", metricStruct.Unit)
	// 判断算子是否支持单层
	if db != chCommon.DB_NAME_FLOW_LOG {
		unlayFuns := metrics.METRICS_TYPE_UNLAY_FUNCTIONS[metricStruct.Type]
		if common.IsValueInSliceString(name, unlayFuns) {
			levelFlag = view.MODEL_METRICS_LEVEL_FLAG_UNLAY
		} else {
			levelFlag = view.MODEL_METRICS_LEVEL_FLAG_LAYERED
		}
	} else {
		levelFlag = view.MODEL_METRICS_LEVEL_FLAG_UNLAY
	}
	if isDerivative {
		levelFlag = view.MODEL_METRICS_LEVEL_FLAG_LAYERED
	}
	return &AggFunction{
		Metrics:           metricStruct,
		Name:              name,
		Args:              args,
		Alias:             alias,
		IsDerivative:      isDerivative,
		DerivativeGroupBy: derivativeGroupBy,
	}, levelFlag, unit, nil
}

func GetTopKTrans(name string, args []string, alias string, db string, table string, ctx context.Context) (Statement, int, string, error) {
	function, ok := metrics.METRICS_FUNCTIONS_MAP[name]
	if !ok {
		return nil, 0, "", nil
	}

	var fields []string
	if name == view.FUNCTION_TOPK {
		fields = args[:len(args)-1]
	} else if name == view.FUNCTION_ANY {
		fields = args
	}
	if name == view.FUNCTION_TOPK {
		topCountStr := args[len(args)-1]
		topCount, err := strconv.Atoi(topCountStr)
		if err != nil {
			return nil, 0, "", fmt.Errorf("function [%s] argument is not int [%s]", view.FUNCTION_TOPK, topCountStr)
		}
		if topCount < 1 || topCount > 100 {
			return nil, 0, "", fmt.Errorf("function [%s] argument [%s] value range is incorrect, it should be within [1, 100]", view.FUNCTION_TOPK, topCountStr)
		}
	}
	levelFlag := view.MODEL_METRICS_LEVEL_FLAG_UNLAY

	fieldsLen := len(fields)
	dbFields := make([]string, fieldsLen)
	conditions := make([]string, 0, fieldsLen)

	var metricStruct *metrics.Metrics
	for i, field := range fields {
		var condition string

		field = strings.Trim(field, "`")
		metricStruct, ok = metrics.GetAggMetrics(field, db, table, ctx)
		if !ok || metricStruct.Type == metrics.METRICS_TYPE_ARRAY {
			return nil, 0, "", nil
		}

		condition = metricStruct.Condition
		tag, ok := tag.GetTag(field, db, table, "default")
		if ok {
			dbFields[i] = tag.TagTranslator
			if condition == "" {
				condition = tag.NotNullFilter
			}
		} else {
			dbFields[i] = metricStruct.DBField
		}
		if condition != "" {
			conditions = append(conditions, condition)
		}

		// 判断算子是否支持单层
		if levelFlag == view.MODEL_METRICS_LEVEL_FLAG_UNLAY && db != chCommon.DB_NAME_FLOW_LOG {
			unlayFuns := metrics.METRICS_TYPE_UNLAY_FUNCTIONS[metricStruct.Type]
			if !common.IsValueInSliceString(name, unlayFuns) {
				levelFlag = view.MODEL_METRICS_LEVEL_FLAG_LAYERED
			}
		}
	}

	metricStructCopy := *metricStruct
	if fieldsLen > 1 {
		metricStructCopy.DBField = "(" + strings.Join(dbFields, ", ") + ")"
		metricStructCopy.Condition = "(" + strings.Join(conditions, " AND ") + ")"
	} else {
		metricStructCopy.DBField = strings.Join(dbFields, ", ")
		metricStructCopy.Condition = strings.Join(conditions, " AND ")
	}

	unit := strings.ReplaceAll(function.UnitOverwrite, "$unit", metricStruct.Unit)

	return &AggFunction{
		Metrics: &metricStructCopy,
		Name:    name,
		Args:    args,
		Alias:   alias,
	}, levelFlag, unit, nil
}

func GetBinaryFunc(name string, args []Function) (*BinaryFunction, error) {
	return &BinaryFunction{
		Name:      name,
		Functions: args,
	}, nil
}

func GetFieldFunc(name string) (FieldFunction, error) {
	switch strings.ToLower(name) {
	case "time_interval":
		return &TimeIntervalField{}, nil
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
		fieldFunc := field.Trans(m)
		fields = append(fields, fieldFunc)
	}
	if f.Name == view.FUNCTION_HISTOGRAM {
		hisInnerName := fields[0].(view.Function).GetDefaultAlias(true)
		hisInnerName = fmt.Sprintf("`%s`", strings.Trim(hisInnerName, "`"))
		fields[0].(view.Function).SetAlias(hisInnerName, true)
		fields[0].(view.Function).SetFlag(view.METRICS_FLAG_OUTER)
		m.AddTag(fields[0])
		histogram := view.GetFunc(f.Name)
		histogram.SetFields([]view.Node{&view.Field{Value: hisInnerName}, fields[1]})
		histogram.SetFlag(view.METRICS_FLAG_TOP)
		histogram.Init()
		return histogram
	} else if f.Name == view.FUNCTION_PCTL || f.Name == view.FUNCTION_PCTL_EXACT {
		function := view.GetFunc(f.Name)
		function.SetFields(fields[:1])                   // metrics
		function.SetArgs([]string{fields[1].ToString()}) // quantile percentage
		function.SetFlag(view.METRICS_FLAG_OUTER)
		function.SetTime(m.Time)
		function.Init()
		return function
	}
	function := view.GetFunc(f.Name)
	function.SetFields(fields)
	function.SetFlag(view.METRICS_FLAG_OUTER)
	function.SetTime(m.Time)
	function.Init()
	return function
}

func (f *BinaryFunction) Format(m *view.Model) {
	function := f.Trans(m)
	if aggfunc, ok := function.(view.Function); ok {
		aggfunc.SetAlias(f.Alias, false)
		m.AddTag(aggfunc)
	} else {
		m.AddTag(function)
	}
}

func (f *BinaryFunction) SetAlias(alias string) {
	f.Alias = alias
}

type AggFunction struct {
	// 指标量内容
	Metrics *metrics.Metrics
	// 解析获得的参数
	Name              string
	Args              []string
	Alias             string
	IsDerivative      bool
	DerivativeGroupBy []string
}

func (f *AggFunction) SetAlias(alias string) {
	f.Alias = alias
}

func (f *AggFunction) FormatInnerTag(m *view.Model) (innerAlias string) {
	switch f.Metrics.Type {
	case metrics.METRICS_TYPE_COUNTER, metrics.METRICS_TYPE_GAUGE:
		// 计数类和油标类，内层结构为sum
		// 内层算子使用默认alias
		var innerFunction view.DefaultFunction
		// Inner layer derivative
		if f.IsDerivative {
			groupBy := []string{}
			if len(f.Args) > 1 {
				groupBy = f.Args[1:]
			}
			innerFunction = view.DefaultFunction{
				Name:   view.FUNCTION_DERIVATIVE,
				Fields: []view.Node{&view.Field{Value: f.Metrics.DBField}},
				Args:   groupBy,
			}
		} else {
			innerFunction = view.DefaultFunction{
				Name:   view.FUNCTION_SUM,
				Fields: []view.Node{&view.Field{Value: f.Metrics.DBField}},
			}
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_DELAY, metrics.METRICS_TYPE_BOUNDED_GAUGE:
		// 时延类，内层结构为groupArray，忽略0值
		innerFunction := view.DefaultFunction{
			Name:       view.FUNCTION_GROUP_ARRAY,
			Fields:     []view.Node{&view.Field{Value: f.Metrics.DBField}},
			IgnoreZero: true,
		}
		// When using avg, max, and min operators. The inner layer uses itself
		if slices.Contains([]string{view.FUNCTION_AVG, view.FUNCTION_MAX, view.FUNCTION_MIN}, f.Name) {
			innerFunction = view.DefaultFunction{
				Name:   f.Name,
				Fields: []view.Node{&view.Field{Value: f.Metrics.DBField}},
			}
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
			DivType: view.FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL,
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_TAG:
		innerFunction := view.DefaultFunction{
			Name:      view.FUNCTION_GROUP_ARRAY,
			Fields:    []view.Node{&view.Field{Value: f.Metrics.DBField}},
			Condition: f.Metrics.Condition,
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_OTHER:
		innerFunction := view.DefaultFunction{
			Name:   view.FUNCTION_COUNT,
			Fields: []view.Node{&view.Field{Value: "1"}},
		}
		innerAlias = innerFunction.SetAlias("_count_1", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	}
	return ""
}

func (f *AggFunction) Trans(m *view.Model) view.Node {
	var outFunc view.Function
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED && f.Name == view.FUNCTION_COUNT {
		outFunc = &view.DefaultFunction{Name: view.FUNCTION_SUM}
	} else {
		outFunc = view.GetFunc(f.Name)
	}
	if len(f.Args) > 1 && !m.IsDerivative {
		outFunc.SetArgs(f.Args[1:])
	}
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED {
		// When Avg is forced (due to the need for other metrics in the same statement)
		// to use two layers of SQL calculation, the calculation logic of AAvg is directly used
		if f.Name == view.FUNCTION_AVG {
			outFunc = view.GetFunc(view.FUNC_NAME_MAP[view.FUNCTION_AAVG])
		}
		innerAlias := f.FormatInnerTag(m)
		switch f.Metrics.Type {
		case metrics.METRICS_TYPE_COUNTER, metrics.METRICS_TYPE_GAUGE:
			// 计数类和油标类，null需要补成0
			outFunc.SetFillNullAsZero(true)
		case metrics.METRICS_TYPE_DELAY, metrics.METRICS_TYPE_BOUNDED_GAUGE:
			// 时延类和商值类，忽略0值
			// When using avg, max, and min operators. The outer layer uses itself
			if !slices.Contains([]string{view.FUNCTION_AVG, view.FUNCTION_MAX, view.FUNCTION_MIN}, f.Name) {
				outFunc.SetIsGroupArray(true)
			}
			outFunc.SetIgnoreZero(true)
		case metrics.METRICS_TYPE_PERCENTAGE:
			outFunc.SetFillNullAsZero(true)
			outFunc.SetMath("*100")
		case metrics.METRICS_TYPE_TAG:
			outFunc.SetIsGroupArray(true)
		}
		outFunc.SetFields([]view.Node{&view.Field{Value: innerAlias}})
	} else if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_UNLAY {
		switch f.Metrics.Type {
		case metrics.METRICS_TYPE_COUNTER, metrics.METRICS_TYPE_GAUGE:
			// Counter/Gauge type weighted average
			if f.Name == view.FUNCTION_AVG {
				outFunc = view.GetFunc(view.FUNCTION_COUNTER_AVG)
			}
		case metrics.METRICS_TYPE_BOUNDED_GAUGE:
			if f.Name == view.FUNCTION_AVG {
				outFunc = view.GetFunc(view.FUNC_NAME_MAP[view.FUNCTION_AAVG])
			}
		case metrics.METRICS_TYPE_DELAY:
			// Delay type weighted average
			if f.Name == view.FUNCTION_AVG {
				outFunc = view.GetFunc(view.FUNCTION_DELAY_AVG)
			}
			outFunc.SetIgnoreZero(true)
		case metrics.METRICS_TYPE_QUOTIENT:
			// Quotient type weighted average
			if f.Name == view.FUNCTION_AVG {
				outFunc = view.GetFunc(view.FUNCTION_DELAY_AVG)
			}
		case metrics.METRICS_TYPE_PERCENTAGE:
			// Percentage type weighted average
			if f.Name == view.FUNCTION_AVG {
				outFunc = view.GetFunc(view.FUNCTION_DELAY_AVG)
			}
			outFunc.SetMath("*100")
		}
		if f.Metrics.Condition != "" {
			outFunc.SetCondition(f.Metrics.Condition)
		}
		field := f.Metrics.DBField
		if f.Name == view.FUNCTION_COUNT {
			field = "1"
		}
		outFunc.SetFields([]view.Node{&view.Field{Value: field}})
	}
	outFunc.SetFlag(view.METRICS_FLAG_OUTER)
	outFunc.SetTime(m.Time)
	outFunc.Init()
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

type TimeIntervalField struct {
	FieldFunction
}

func (f *TimeIntervalField) Format(m *view.Model) {}

func (f *TimeIntervalField) Trans(m *view.Model) view.Node {
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

func (f *TimeIntervalField) SetAlias(alias string) {}

type Time struct {
	Args       []string
	Alias      string
	Withs      []view.Node
	TimeField  string
	Interval   int
	WindowSize int
	Offset     int
	Fill       string
}

func (t *Time) Trans(m *view.Model) error {
	t.TimeField = strings.ReplaceAll(t.Args[0], "`", "")
	floatInterval, err := strconv.ParseFloat(t.Args[1], 64)
	intInterval := int(math.Ceil(floatInterval))
	t.Interval = intInterval
	if err != nil {
		return err
	}
	if len(t.Args) > 2 {
		t.WindowSize, err = strconv.Atoi(t.Args[2])
		if err != nil {
			return err
		}
	} else {
		t.WindowSize = 1
	}
	if len(t.Args) > 3 {
		t.Fill = t.Args[3]
	}
	if len(t.Args) > 4 {
		t.Offset, err = strconv.Atoi(t.Args[4])
		if err != nil {
			return err
		}
	}
	m.Time.Interval = t.Interval
	if m.Time.Interval > 0 && m.Time.Interval < m.Time.DatasourceInterval {
		m.Time.Interval = m.Time.DatasourceInterval
	}
	m.Time.WindowSize = t.WindowSize
	m.Time.Fill = t.Fill
	m.Time.Offset = t.Offset
	m.Time.Alias = t.Alias
	return nil
}

func (t *Time) Format(m *view.Model) {
	toIntervalFunction := "toIntervalSecond"
	interval := m.Time.Interval
	toDatasourceIntervalFunction := "toIntervalSecond"
	datasourceInterval := m.Time.DatasourceInterval
	if interval >= INTERVAL_1D {
		toIntervalFunction = "toIntervalDay"
		interval = interval / INTERVAL_1D
	}
	if datasourceInterval >= INTERVAL_1D {
		toDatasourceIntervalFunction = "toIntervalDay"
		datasourceInterval = datasourceInterval / INTERVAL_1D
	}
	var windows string
	w := make([]string, t.WindowSize)
	for i := range w {
		w[i] = strconv.Itoa(i)
	}
	windows = strings.Join(w, ",")
	var innerTimeField string
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED {
		innerTimeField = "_" + t.TimeField
		withValue := ""
		if m.IsDerivative {
			offset := m.Time.Offset
			if offset > 0 {
				withValue = fmt.Sprintf(
					"toStartOfInterval(time-%d, %s(%d)) + %s(arrayJoin([%s]) * %d) + %d",
					offset, toIntervalFunction, interval, toIntervalFunction, windows, interval, offset,
				)
			} else {
				withValue = fmt.Sprintf(
					"toStartOfInterval(time, %s(%d)) + %s(arrayJoin([%s]) * %d)",
					toIntervalFunction, interval, toIntervalFunction, windows, interval,
				)
			}
		} else {
			withValue = fmt.Sprintf(
				"toStartOfInterval(%s, %s(%d))",
				t.TimeField, toDatasourceIntervalFunction, datasourceInterval,
			)
		}

		withAlias := "_" + t.TimeField
		withs := []view.Node{&view.With{Value: withValue, Alias: withAlias}}
		m.AddTag(&view.Tag{Value: withAlias, Withs: withs, Flag: view.NODE_FLAG_METRICS_INNER})
		m.AddGroup(&view.Group{Value: withAlias, Flag: view.GROUP_FLAG_METRICS_INNTER})
	} else if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_UNLAY {
		innerTimeField = t.TimeField
	}
	offset := m.Time.Offset
	withValue := ""
	if offset > 0 {
		withValue = fmt.Sprintf(
			"toStartOfInterval(%s-%d, %s(%d)) + %s(arrayJoin([%s]) * %d) + %d",
			innerTimeField, offset, toIntervalFunction, interval, toIntervalFunction, windows, interval, offset,
		)
	} else {
		withValue = fmt.Sprintf(
			"toStartOfInterval(%s, %s(%d)) + %s(arrayJoin([%s]) * %d)",
			innerTimeField, toIntervalFunction, interval, toIntervalFunction, windows, interval,
		)
	}
	withAlias := "_" + strings.Trim(t.Alias, "`")
	withs := []view.Node{&view.With{Value: withValue, Alias: withAlias}}
	tagField := fmt.Sprintf("toUnixTimestamp(`%s`)", withAlias)
	if m.IsDerivative {
		tagField = fmt.Sprintf("toUnixTimestamp(`%s`)", innerTimeField)
		m.AddTag(&view.Tag{Value: tagField, Alias: t.Alias, Flag: view.NODE_FLAG_METRICS_OUTER})
	} else {
		m.AddTag(&view.Tag{Value: tagField, Alias: t.Alias, Flag: view.NODE_FLAG_METRICS_OUTER, Withs: withs})
	}
	m.AddGroup(&view.Group{Value: t.Alias, Flag: view.GROUP_FLAG_METRICS_OUTER})
	if m.Time.Fill != "" && m.Time.Interval > 0 {
		m.AddCallback("time", TimeFill([]interface{}{m}))
	}
}

type TagFunction struct {
	Name  string
	Args  []string
	Alias string
	Withs []view.Node
	Value string
	DB    string
	Table string
}

func (f *TagFunction) SetAlias(alias string) {
	f.Alias = alias
}

func (f *TagFunction) getViewNode() view.Node {
	if f.Value == "" {
		return &view.Tag{Value: fmt.Sprintf("`%s`", strings.Trim(f.Alias, "`")), Withs: f.Withs}
	} else {
		return &view.Tag{Value: f.Value, Alias: f.Alias}
	}
}

func (f *TagFunction) Check() error {
	switch f.Name {
	case TAG_FUNCTION_MASK:
		_, ok := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		if !ok {
			return errors.New(fmt.Sprintf("function mask not support %s", f.Args[0]))
		}
		maskInt, err := strconv.Atoi(f.Args[1])
		if err != nil {
			return err
		}
		if maskInt < 32 {
			ip4Mask := net.CIDRMask(maskInt, 32)
			_, err = strconv.ParseUint(ip4Mask.String(), 16, 64)
			if err != nil {
				return err
			}
		}
	case TAG_FUNCTION_ICON_ID:
		_, ok := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		if !ok {
			return errors.New(fmt.Sprintf("function %s not support %s", f.Name, f.Args[0]))
		}
	case TAG_FUNCTION_ENUM:
		if f.DB == "flow_tag" {
			_, ok := tag.GetTag("enum_tag_name", f.DB, f.Table, f.Name)
			if !ok {
				return errors.New(fmt.Sprintf("function %s not support %s", f.Name, f.Args[0]))
			}
		} else {
			_, ok := tag.GetTag(strings.Trim(f.Args[0], "`"), f.DB, f.Table, f.Name)
			if !ok {
				return errors.New(fmt.Sprintf("function %s not support %s", f.Name, f.Args[0]))
			}
		}
	case TAG_FUNCTION_FAST_FILTER:
		if strings.Trim(f.Args[0], "`") != "trace_id" {
			return errors.New(fmt.Sprintf("function %s not support %s", f.Name, f.Args[0]))
		}
	}
	return nil

}

func (f *TagFunction) Trans(m *view.Model) view.Node {
	fields := f.Args
	switch f.Name {
	case TAG_FUNCTION_ANY:
		f.Name = "any"
	case TAG_FUNCTION_TOPK:
		f.Name = fmt.Sprintf("topK(%s)", f.Args[len(f.Args)-1])
		fields = fields[:len(f.Args)-1]
	case TAG_FUNCTION_MASK:
		tagDes, _ := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		if f.Alias == "" {
			f.Alias = "mask"
		}
		maskInt, _ := strconv.Atoi(f.Args[1])
		var ip4MaskInt uint64
		if maskInt >= 32 {
			ip4MaskInt = 4294967295
		} else {
			ip4Mask := net.CIDRMask(maskInt, 32)
			ip4MaskInt, _ = strconv.ParseUint(ip4Mask.String(), 16, 64)
		}
		ip6Mask := net.CIDRMask(maskInt, 128)
		value := fmt.Sprintf(tagDes.TagTranslator, ip4MaskInt, ip6Mask.String())
		f.Withs = []view.Node{&view.With{Value: value, Alias: f.Alias}}
		return f.getViewNode()
	case TAG_FUNCTION_NODE_TYPE:
		tagDes, ok := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		if ok {
			f.Value = tagDes.TagTranslator
		} else {
			// Custom Tag
			if strings.HasPrefix(f.Args[0], "k8s.label.") || strings.HasPrefix(f.Args[0], "k8s.annotation.") || strings.HasPrefix(f.Args[0], "k8s.env.") || strings.HasPrefix(f.Args[0], "cloud.tag.") || strings.HasPrefix(f.Args[0], "os.app.") {
				nodeType := strings.TrimSuffix(f.Args[0], "_0")
				nodeType = strings.TrimSuffix(nodeType, "_1")
				f.Value = "'" + nodeType + "'"
			} else {
				nodeType := strings.Trim(f.Args[0], "'")
				nodeType = strings.TrimSuffix(nodeType, "0")
				nodeType = strings.TrimSuffix(nodeType, "1")
				f.Value = "'" + nodeType + "'"
			}
		}

		if strings.HasPrefix(f.Args[0], "is_internet") {
			m.AddGroup(&view.Group{Value: fmt.Sprintf("`%s`", strings.Trim(f.Alias, "`"))})
		}

		return f.getViewNode()
	case TAG_FUNCTION_ICON_ID:
		tagDes, _ := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		f.Withs = []view.Node{&view.With{Value: tagDes.TagTranslator, Alias: f.Alias}}

		if strings.HasPrefix(f.Args[0], "is_internet") {
			m.AddGroup(&view.Group{Value: fmt.Sprintf("`%s`", strings.Trim(f.Alias, "`"))})
		}

		return f.getViewNode()
	case TAG_FUNCTION_TO_STRING:
		if common.IsValueInSliceString(f.Args[0], []string{"start_time", "end_time"}) {
			tagDes, _ := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
			f.Value = tagDes.TagTranslator
			return f.getViewNode()
		}
	case TAG_FUNCTION_NEW_TAG:
		f.Value = f.Args[0]
		if f.Alias == "" {
			f.Alias = fmt.Sprintf("new_tag_%s", f.Args[0])
		}
		node := f.getViewNode()
		// node.(*view.Tag).Flag = view.NODE_FLAG_METRICS_TOP
		return node
	case TAG_FUNCTION_ENUM:
		var tagFilter string
		tagEnum := strings.TrimSuffix(f.Args[0], "_0")
		tagEnum = strings.TrimSuffix(tagEnum, "_1")
		tagDes, getTagOK := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		tagDescription, tagOK := tag.TAG_DESCRIPTIONS[tag.TagDescriptionKey{
			DB: f.DB, Table: f.Table, TagName: f.Args[0],
		}]

		if getTagOK {
			if tagOK {
				enumFileName := strings.TrimSuffix(tagDescription.EnumFile, "."+config.Cfg.Language)
				tagFilter = fmt.Sprintf(tagDes.TagTranslator, enumFileName)
			} else {
				tagFilter = fmt.Sprintf(tagDes.TagTranslator, tagEnum)
			}
		} else {
			tagFilter = fmt.Sprintf("Enum(%s)", f.Args[0])
		}
		if f.Alias == "" {
			f.Alias = fmt.Sprintf("Enum(%s)", f.Args[0])
		}
		f.Withs = []view.Node{&view.With{Value: tagFilter, Alias: f.Alias}}
		return f.getViewNode()
	}
	values := make([]string, len(fields))
	for i, field := range fields {
		var tagField string
		tagDes, ok := tag.GetTag(field, f.DB, f.Table, f.Name)
		if !ok {
			// tag未定义function则走default
			tagDes, ok = tag.GetTag(field, f.DB, f.Table, "default")
			if ok {
				tagField = tagDes.TagTranslator
			}
		} else {
			tagField = tagDes.TagTranslator
		}
		if tagField == "" {
			tagField = field
		}
		values[i] = tagField
	}
	var withValue string
	if len(fields) > 1 {
		if f.Name == "if" {
			withValue = fmt.Sprintf("%s(%s)", f.Name, strings.Join(values, ","))
		} else if strings.HasPrefix(f.Name, "topK") || strings.HasPrefix(f.Name, "any") {
			withValue = fmt.Sprintf("%s((%s))", f.Name, strings.Join(values, ","))
		} else {
			withValue = fmt.Sprintf("%s([%s])", f.Name, strings.Join(values, ","))
		}
	} else {
		withValue = fmt.Sprintf("%s(%s)", f.Name, values[0])
	}
	if f.Alias == "" {
		f.Value = withValue
	} else {
		f.Withs = []view.Node{&view.With{Value: withValue, Alias: f.Alias}}
	}
	return f.getViewNode()
}

func (f *TagFunction) Format(m *view.Model) {
	if strings.HasPrefix(f.Name, TAG_FUNCTION_TOPK) {
		if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED {
			var outAlias string
			alias := strings.Trim(f.Alias, "`")
			innerAlias := fmt.Sprintf("`_%s`", alias)
			outAlias, f.Alias = f.Alias, innerAlias
			node := f.Trans(m)
			node.(*view.Tag).Flag = view.NODE_FLAG_METRICS_INNER
			m.AddTag(node)
			grouparrayNode := &view.Tag{
				Value: fmt.Sprintf("groupUniqArrayArray(%s)", innerAlias),
				Alias: outAlias,
				Flag:  view.NODE_FLAG_METRICS_OUTER,
			}
			m.AddTag(grouparrayNode)
			return
		}
	}
	node := f.Trans(m)
	m.AddTag(node)
	if f.Name == TAG_FUNCTION_ICON_ID {
		for resourceStr := range tag.DEVICE_MAP {
			// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
			for _, suffix := range []string{"", "_0", "_1"} {
				resourceNameSuffix := resourceStr + suffix
				if f.Args[0] == resourceNameSuffix {
					m.AddGroup(&view.Group{Value: fmt.Sprintf("`%s`", strings.Trim(f.Alias, "`"))})
				}
			}
		}
	}
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED && node.(*view.Tag).Flag != view.NODE_FLAG_METRICS_TOP {
		// metric分层的情况下 function需加入metric外层group
		m.AddGroup(&view.Group{Value: fmt.Sprintf("`%s`", strings.Trim(f.Alias, "`")), Flag: view.GROUP_FLAG_METRICS_OUTER})
	}
	// 拆层至3层时newTag需要被添加至最外层返回
	if f.Name == TAG_FUNCTION_NEW_TAG {
		nodeTag := node.(*view.Tag)
		newTag := view.Tag{Value: nodeTag.Value, Alias: nodeTag.Alias, Withs: nodeTag.Withs, Flag: view.NODE_FLAG_METRICS_TOP}
		m.AddTag(&newTag)
	}
}
