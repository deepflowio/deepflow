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
			Model.AddFilter()
			NewView(*Model) View      使用model初始化View结构
			NewView.ToString() string 生成df-clickhouse-sql
*/
type Model struct {
	Tags    *Tags
	Filters *Filters
	From    *Tables
	Groups  *Groups
	//Havings Havings
	//Order   Order
	MetricLevelFlag int //Metric是否需要拆层的标识
}

func NewModel() *Model {
	return &Model{
		Tags:    &Tags{},
		Groups:  &Groups{},
		From:    &Tables{},
		Filters: &Filters{},
	}
}

func (m *Model) AddTag(n Node) {
	m.Tags.Append(n)
}

func (m *Model) AddFilter(f *Filters) {
	m.Filters.Append(f)
}

func (m *Model) AddTable(value string) {
	m.From.Append(&Table{Value: value})
}

func (m *Model) AddGroup(g *Group) {
	m.Groups.Append(g)
}

type View struct {
	Model         *Model     //初始化view
	SubViewLevels []*SubView //由RawView拆层
}

// 使用model初始化view
func NewView(m *Model) View {
	return View{Model: m}
}

func (v *View) ToString() string {
	buf := bytes.Buffer{}
	v.trans()
	for i, view := range v.SubViewLevels {
		if i > 0 {
			// 将内层view作为外层view的From
			view.From.Append(v.SubViewLevels[i-1])
		}
	}
	//从最外层View开始拼接sql
	v.SubViewLevels[len(v.SubViewLevels)-1].WriteTo(&buf)
	return buf.String()
}

func (v *View) trans() {
	var tagsLevelInner []Node
	var tagsLevelMetric []Node
	var tagsLevelOuter []Node
	// 遍历tags，解析至分层结构中
	for _, tag := range v.Model.Tags.tags {
		switch node := tag.(type) {
		case *Tag:
			if node.Flag == NODE_FLAG_METRIC {
				// Tag在最内层中只保留value 去掉alias
				tagsLevelInner = append(tagsLevelInner, &Tag{Value: node.Value})
				tagsLevelMetric = append(tagsLevelMetric, tag)
			} else if node.Flag == NODE_FLAG_TRANS {
				// 需要放入最外层的tag
				tagsLevelOuter = append(tagsLevelOuter, tag)
			}
		case Function:
			flag := node.GetFlag()
			if flag == METRIC_FLAG_INNER {
				tagsLevelInner = append(tagsLevelInner, tag)
			} else if flag == METRIC_FLAG_OUTER {
				tagsLevelMetric = append(tagsLevelMetric, tag)
			}
		}
	}
	if v.Model.MetricLevelFlag == MODEL_METRIC_LEVEL_FLAG_UNLAY {
		// 计算层不拆层
		sv := SubView{
			Tags:    &Tags{tags: tagsLevelMetric},
			Groups:  v.Model.Groups,
			From:    v.Model.From,
			Filters: v.Model.Filters,
		}
		v.SubViewLevels = append(v.SubViewLevels, &sv)
	} else if v.Model.MetricLevelFlag == MODEL_METRIC_LEVEL_FLAG_LAYERED {
		// 计算层需要拆层
		// 计算层里层
		svInner := SubView{
			Tags:    &Tags{tags: tagsLevelInner}, // 计算层所有tag及里层算子
			Groups:  v.Model.Groups,              // TODO:group分层
			From:    v.Model.From,                // 查询表
			Filters: v.Model.Filters,             // 所有filter
		}
		v.SubViewLevels = append(v.SubViewLevels, &svInner)
		// 计算层外层
		svMetric := SubView{
			Tags:    &Tags{tags: tagsLevelMetric}, // 计算层所有tag及外层算子
			Groups:  v.Model.Groups,               // TODO:group分层
			From:    &Tables{},                    // 空table
			Filters: &Filters{},                   // 空filter
		}
		v.SubViewLevels = append(v.SubViewLevels, &svMetric)
	}
	if tagsLevelOuter != nil {
		// 翻译层
		svOuter := SubView{
			Tags:    &Tags{tags: tagsLevelOuter}, // 所有翻译层tag
			Groups:  &Groups{},                   // 空group
			From:    &Tables{},                   // 空table
			Filters: &Filters{},                  //空filter
		}
		v.SubViewLevels = append(v.SubViewLevels, &svOuter)
	}
}

type SubView struct {
	Tags    *Tags
	Filters *Filters
	From    *Tables
	Groups  *Groups
	//Havings Havings
	//Order   Order
}

func (sv *SubView) GetWiths() []Node {
	var withs []Node
	if nodeWiths := sv.Tags.GetWiths(); nodeWiths != nil {
		withs = append(withs, nodeWiths...)
	}
	if nodeWiths := sv.Filters.GetWiths(); nodeWiths != nil {
		withs = append(withs, nodeWiths...)
	}
	if nodeWiths := sv.Groups.GetWiths(); nodeWiths != nil {
		withs = append(withs, nodeWiths...)
	}
	return withs
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
	if nodeWiths := sv.GetWiths(); nodeWiths != nil {
		withs := Withs{Withs: nodeWiths}
		withs.Withs = sv.removeDup(&withs)
		buf.WriteString("WITH ")
		withs.WriteTo(buf)
	}
	if !sv.Tags.IsNull() {
		sv.Tags.tags = sv.removeDup(sv.Tags)
		buf.WriteString("SELECT ")
		sv.Tags.WriteTo(buf)
	}
	if !sv.From.IsNull() {
		buf.WriteString(" FROM ")
		sv.From.WriteTo(buf)
	}
	if !sv.Filters.IsNull() {
		buf.WriteString(" WHERE ")
		sv.Filters.WriteTo(buf)
	}
	if !sv.Groups.IsNull() {
		sv.Groups.groups = sv.removeDup(sv.Groups)
		buf.WriteString(" GROUP BY ")
		sv.Groups.WriteTo(buf)
	}
}

type Node interface {
	ToString() string
	WriteTo(*bytes.Buffer)
	GetWiths() []Node
}

type NodeSet interface {
	Node
	IsNull() bool
	getList() []Node
}

type NodeBase struct{}

func (n *NodeBase) GetWiths() []Node {
	return nil
}

type NodeSetBase struct{ NodeBase }
