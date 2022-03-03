package view

import (
	"bytes"
)

/*
	对外接口：
		struct：
			Model 包含withs tags filters等结构用于构造view
			View  由Model生成，用于构造df-clickhouse-sql
		func：
			NewModel() Model          初始化Model结构
			Model.AddTag()
			Model.AddTable()
			Model.AddGroup()
			Model.AddWith()
			NewView(*Model) View      使用model初始化View结构
			NewView.ToString() string 生成df-clickhouse-sql
*/
type Model struct {
	Withs *Withs
	Tags  *Tags
	//Metrics Metrics
	//Filters []*Filters
	From   *Tables
	Groups *Groups
	//Havings Havings
	//Order   Order
}

func NewModel() *Model {
	return &Model{
		Withs:  &Withs{},
		Tags:   &Tags{},
		Groups: &Groups{},
		From:   &Tables{},
	}
}

func (m *Model) AddTag(value string, alias string, flag int) {
	m.Tags.Append(&Tag{Value: value, Alias: alias, Flag: flag})
}

func (m *Model) AddTable(value string) {
	m.From.Append(&Table{Value: value})
}

func (m *Model) AddGroup(value string, flag int) {
	m.Groups.Append(&Group{Value: value})
}

func (m *Model) AddWith(value string, alias string, flag int) {
	m.Withs.Append(&With{Value: value, Alias: alias, Flag: flag})
}

type View struct {
	Model         *Model     //初始化view
	SubViewLevels []*SubView //由RawView拆层
	LevelTag      int        //层级tag
}

// 使用model初始化view
func NewView(m *Model) View {
	return View{Model: m, LevelTag: 1}
}

func (v *View) ToString() string {
	buf := bytes.Buffer{}
	v.trans()
	for i, view := range v.SubViewLevels {
		if i > 1 {
			// 将内层view作为外层view的From
			view.From.Append(v.SubViewLevels[i-1])
		}
	}
	//从最外层View开始拼接sql
	v.SubViewLevels[len(v.SubViewLevels)-1].WriteTo(&buf)
	return buf.String()
}

// TODO：由rawview向多层结构转换
func (v *View) trans() {
	if v.LevelTag == 1 {
		sv := SubView{
			Withs:  v.Model.Withs,
			Tags:   v.Model.Tags,
			Groups: v.Model.Groups,
			From:   v.Model.From,
		}
		v.SubViewLevels = append(v.SubViewLevels, &sv)
	}
}

type SubView struct {
	Withs *Withs
	Tags  *Tags
	//Metrics Metrics
	//Filters *Filters
	From   *Tables
	Groups *Groups
	//Havings Havings
	//Order   Order
}

func (sv *SubView) ToString() string {
	buf := bytes.Buffer{}
	sv.WriteTo(&buf)
	return buf.String()
}

func (sv *SubView) removeDup(ns NodeSet) []Node {
	// 对NodeSet集合去重
	tmpMap := make(map[string]interface{})
	nodeList := ns.getList()
	targetList := nodeList[:0]
	for _, node := range nodeList {
		str := node.ToString()
		if _, ok := tmpMap[str]; !ok {
			targetList = append(targetList, node)
		}
	}
	return targetList
}

func (sv *SubView) WriteTo(buf *bytes.Buffer) {
	if !sv.Withs.isNull() {
		sv.Withs.withs = sv.removeDup(sv.Withs)
		buf.WriteString("WITH ")
		sv.Withs.WriteTo(buf)
	}
	if !sv.Tags.isNull() {
		sv.Tags.tags = sv.removeDup(sv.Tags)
		buf.WriteString("SELECT ")
		sv.Tags.WriteTo(buf)
	}
	/* 	if !sv.Filters.isNull() {
		buf.WriteString(" WHERE ")
		sv.Filters.WriteTo(buf)
	} */
	if !sv.From.isNull() {
		buf.WriteString(" FROM ")
		sv.From.WriteTo(buf)
	}
	if !sv.Groups.isNull() {
		buf.WriteString(" GROUP BY ")
		sv.Groups.WriteTo(buf)
	}
}

type Node interface {
	ToString() string
	WriteTo(*bytes.Buffer)
}

type NodeSet interface {
	Node
	isNull() bool
	getList() []Node
}
