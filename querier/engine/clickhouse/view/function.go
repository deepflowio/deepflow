package view

import (
	"bytes"
)

const (
	FUNCTION_SUM        = "Sum"
	FUNCTION_MAX        = "Max"
	FUNCTION_MIN        = "Min"
	FUNCTION_PCTL       = "Percentile"
	FUNCTION_PCTL_EXACT = "PercentileExact"
	FUNCTION_Apdex      = "Apdex"
)

// 对外提供的算子与数据库实际算子转换
var FUNC_NAME_MAP map[string]string = map[string]string{
	FUNCTION_SUM:        "SUM",
	FUNCTION_MAX:        "MAX",
	FUNCTION_MIN:        "MIN",
	FUNCTION_PCTL:       "quantile",
	FUNCTION_PCTL_EXACT: "quantileExact",
}

func GetFunc(name string, Is0Meaningful bool) Function {
	switch name {
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
	SetIs0Meaningful(bool)
	GetFlag() int
}

type DefaultFunction struct {
	Name          string   // 算子名称
	Fields        []Node   // 指标量名称
	Args          []string // 其他参数
	Alias         string   // as
	Condition     string   // 算子过滤 例：Condition："code in [1,2]" SUMIf(byte, code in [1,2])
	Math          string   // 算术计算
	Withs         []Node
	Flag          int
	Is0Meaningful bool
	NodeBase
}

func (f *DefaultFunction) GetFlag() int {
	return f.Flag
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
	args := f.Args
	dbFuncName, ok := FUNC_NAME_MAP[f.Name]
	if !ok {
		dbFuncName = f.Name
	}
	buf.WriteString(dbFuncName)
	if f.Condition != "" {
		buf.WriteString("If")
		args = append(args, f.Condition)
	}
	buf.WriteString("(")
	for i, field := range f.Fields {
		field.WriteTo(buf)
		if i < len(f.Fields)-1 || len(args) > 0 {
			buf.WriteString(", ")
		}
	}
	for i, arg := range args {
		buf.WriteString(arg)
		if i < len(args)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(")")
	buf.WriteString(f.Math)
	buf.WriteString(" AS ")
	buf.WriteString(f.Alias)
}

func (f *DefaultFunction) GetDefaultAlias(inner bool) string {
	buf := bytes.Buffer{}
	if inner {
		buf.WriteString("_")
	}
	buf.WriteString(f.Name)
	buf.WriteString("_")
	for _, field := range f.Fields {
		buf.WriteString(field.ToString())
		buf.WriteString("_")
	}

	for i, arg := range f.Args {
		buf.WriteString(arg)
		if i < len(f.Args)-1 {
			buf.WriteString("_")
		}
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

func (f *DefaultFunction) SetIs0Meaningful(is0Meaningful bool) {
	f.Is0Meaningful = is0Meaningful
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
