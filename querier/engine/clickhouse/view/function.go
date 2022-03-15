package view

import (
	"bytes"
	"fmt"
)

const (
	FUNCTION_SUM         = "Sum"
	FUNCTION_MAX         = "Max"
	FUNCTION_MIN         = "Min"
	FUNCTION_AVG         = "Avg"
	FUNCTION_PCTL        = "Percentile"
	FUNCTION_PCTL_EXACT  = "PercentileExact"
	FUNCTION_STDDEV      = "Stddev"
	FUNCTION_SPREAD      = "Spread"
	FUNCTION_RSPREAD     = "Rspread"
	FUNCTION_Apdex       = "Apdex"
	FUNCTION_GROUP_ARRAY = "groupArray"
	FUNCTION_DIV         = "\\"
	FUNCTION_PLUS        = "+"
	FUNCTION_RATE        = "Rate"
)

// 对外提供的算子与数据库实际算子转换
var FUNC_NAME_MAP map[string]string = map[string]string{
	FUNCTION_SUM:         "SUM",
	FUNCTION_MAX:         "MAX",
	FUNCTION_MIN:         "MIN",
	FUNCTION_AVG:         "AVG",
	FUNCTION_PCTL:        "quantile",
	FUNCTION_PCTL_EXACT:  "quantileExact",
	FUNCTION_STDDEV:      "stddevPopStable",
	FUNCTION_GROUP_ARRAY: "groupArray",
}

func GetFunc(name string) Function {
	switch name {
	case FUNCTION_SPREAD:
		return &SpreadFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_RSPREAD:
		return &RspreadFunction{DefaultFunction: DefaultFunction{Name: name}}
	case FUNCTION_Apdex:
		// TODO: apdex
	default:
		return &DefaultFunction{Name: name}
	}
	return nil
}

type Function interface {
	Node
	SetFields([]Node)
	SetArgs([]string)
	SetMath(string)
	SetFlag(int)
	SetAlias(string, bool) string
	GetDefaultAlias(bool) string
	SetIgnoreZero(bool)
	SetFillNullAsZero(bool)
	SetIsGroupArray(bool)
	GetFlag() int
	GetName() string
	Init()
}

type DefaultFunction struct {
	Name           string   // 算子名称
	Fields         []Node   // 指标量名称
	Args           []string // 其他参数
	Alias          string   // as
	Condition      string   // 算子过滤 例：Condition："code in [1,2]" SUMIf(byte, code in [1,2])
	Math           string   // 算术计算
	Withs          []Node
	Flag           int
	IgnoreZero     bool
	FillNullAsZero bool
	IsGroupArray   bool // 是否针对list做聚合，例:SUMArray(rtt_max)
	NodeBase
}

func (f *DefaultFunction) Init() {}

func (f *DefaultFunction) GetFlag() int {
	return f.Flag
}

func (f *DefaultFunction) GetName() string {
	return f.Name
}

func (f *DefaultFunction) GetWiths() []Node {
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
	buf.WriteString(dbFuncName)

	if f.IsGroupArray {
		buf.WriteString("Array")
	}

	// Array后缀算子不支持携带If
	if (f.Condition != "" || f.IgnoreZero) && !f.IsGroupArray {
		buf.WriteString("If")
	}

	if len(f.Args) > 0 {
		buf.WriteString("(")
		for i, arg := range f.Args {
			buf.WriteString(arg)
			if i < len(f.Args)-1 {
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
				buf.WriteString(" != 0")
				if i < len(f.Fields)-1 {
					buf.WriteString(" AND ")
				}
			}
		}
	} else {
		// Array后缀的算子处理0值无意义指标量：MAXArray(arrayFilter(x->x>0), _array)
		for i, field := range f.Fields {
			if f.IgnoreZero {
				field.WriteTo(buf)
			} else {
				buf.WriteString("arrayFilter(x -> x!=0, ")
				field.WriteTo(buf)
				buf.WriteString(")")
			}

			if i < len(f.Fields)-1 {
				buf.WriteString(", ")
			}
		}
	}

	buf.WriteString(")")

	buf.WriteString(f.Math)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString(f.Alias)
	}
}

func (f *DefaultFunction) GetDefaultAlias(inner bool) string {
	buf := bytes.Buffer{}
	if inner {
		buf.WriteString("_")
	}
	buf.WriteString(f.Name)
	buf.WriteString("_")
	for i, field := range f.Fields {
		buf.WriteString(field.ToString())
		if i < len(f.Fields)-1 {
			buf.WriteString("_")
		}
	}

	for _, arg := range f.Args {
		buf.WriteString("_")
		buf.WriteString(arg)
	}
	return buf.String()
}

func (f *DefaultFunction) SetAlias(alias string, inner bool) string {
	if alias == "" {
		alias = f.GetDefaultAlias(inner)
	}
	f.Alias = alias
	return alias
}

func (f *DefaultFunction) SetFields(fields []Node) {
	f.Fields = fields
}

func (f *DefaultFunction) SetMath(math string) {
	f.Math = math
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

type Field struct {
	NodeBase
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

type SpreadFunction struct {
	DefaultFunction
}

func (f *SpreadFunction) WriteTo(buf *bytes.Buffer) {
	maxFunc := DefaultFunction{
		Name:       FUNCTION_MAX,
		Fields:     f.Fields,
		IgnoreZero: f.IgnoreZero,
	}
	minFunc := DefaultFunction{
		Name:       FUNCTION_MIN,
		Fields:     f.Fields,
		IgnoreZero: f.IgnoreZero,
	}
	maxFunc.WriteTo(buf)
	buf.WriteString(" - ")
	minFunc.WriteTo(buf)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString(f.Alias)
	}
}

type RspreadFunction struct {
	DefaultFunction
	divFunction *DivFunction // rspread的实际算子是div
}

func (f *RspreadFunction) Init() {
	maxFunc := DefaultFunction{
		Name:       FUNCTION_MAX,
		Fields:     f.Fields,
		IgnoreZero: f.IgnoreZero,
	}
	minFunc := DefaultFunction{
		Name:       FUNCTION_MIN,
		Fields:     f.Fields,
		IgnoreZero: f.IgnoreZero,
	}
	f.divFunction = &DivFunction{
		DivType: FUNCTION_DIV_TYPE_FILL_MINIMUM,
		DefaultFunction: DefaultFunction{
			Name:       FUNCTION_DIV,
			Fields:     []Node{&maxFunc, &minFunc},
			IgnoreZero: f.IgnoreZero,
		},
	}
}

func (f *RspreadFunction) WriteTo(buf *bytes.Buffer) {
	f.divFunction.WriteTo(buf)
	if f.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString(f.Alias)
	}
}

func (f *RspreadFunction) GetWiths() []Node {
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
		buf.WriteString("divide_0diveider_as_null")
		buf.WriteString(f.Fields[0].(Function).GetDefaultAlias(true))
		buf.WriteString(f.Fields[1].(Function).GetDefaultAlias(true))
	} else if f.DivType == FUNCTION_DIV_TYPE_0DIVIDER_AS_0 {
		buf.WriteString("divide_0diveider_as_0")
		buf.WriteString(f.Fields[0].(Function).GetDefaultAlias(true))
		buf.WriteString(f.Fields[1].(Function).GetDefaultAlias(true))
	}
}

func (f *DivFunction) GetWiths() []Node {
	f.Withs = append(f.Withs, f.Fields[0].GetWiths()...)
	f.Withs = append(f.Withs, f.Fields[1].GetWiths()...)
	if f.DivType == FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL {
		with := fmt.Sprintf(
			"if(%s>0, divide(%s, %s), null) as divide_0diveider_as_null%s%s",
			f.Fields[1].ToString(), f.Fields[0].ToString(), f.Fields[1].ToString(),
			f.Fields[0].(Function).GetDefaultAlias(true),
			f.Fields[1].(Function).GetDefaultAlias(true),
		)
		f.Withs = append(f.Withs, &With{Value: with})
	} else if f.DivType == FUNCTION_DIV_TYPE_0DIVIDER_AS_0 {
		with := fmt.Sprintf(
			"if(%s>0, divide(%s, %s), 0) as divide_0diveider_as_0%s%s",
			f.Fields[1].ToString(), f.Fields[0].ToString(), f.Fields[1].ToString(),
			f.Fields[0].(Function).GetDefaultAlias(true),
			f.Fields[1].(Function).GetDefaultAlias(true),
		)
		f.Withs = append(f.Withs, &With{Value: with})
	}
	return f.Withs
}
