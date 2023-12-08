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

package view

import (
	"bytes"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/common"
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
	DB        string
	Time      *Time
	Tags      *Tags
	Filters   *Filters
	From      *Tables
	Groups    *Groups
	Havings   *Filters
	Orders    *Orders
	Limit     *Limit
	Callbacks map[string]func(*common.Result) error
	//Havings Havings
	MetricsLevelFlag  int //Metrics是否需要拆层的标识
	HasAggFunc        bool
	IsDerivative      bool
	DerivativeGroupBy []string
}

func NewModel() *Model {
	return &Model{
		Time:       NewTime(),
		Tags:       &Tags{},
		Groups:     &Groups{},
		From:       &Tables{},
		Filters:    &Filters{},
		Havings:    &Filters{},
		Orders:     &Orders{},
		Limit:      &Limit{},
		Callbacks:  map[string]func(*common.Result) error{},
		HasAggFunc: false,
	}
}

func (m *Model) AddCallback(col string, f func(*common.Result) error) {
	_, ok := m.Callbacks[col]
	if !ok {
		m.Callbacks[col] = f
	}
}

func (m *Model) AddTag(n Node) {
	m.Tags.Append(n)
}

func (m *Model) AddFilter(f *Filters) {
	m.Filters.Append(f)
}

func (m *Model) AddHaving(f *Filters) {
	m.Havings.Append(f)
}

func (m *Model) AddTable(value string) {
	m.From.Append(&Table{Value: value})
}

func (m *Model) AddGroup(g *Group) {
	m.Groups.Append(g)
}

type Time struct {
	TimeStart          int64
	TimeEnd            int64
	Interval           int
	DatasourceInterval int
	WindowSize         int
	Offset             int
	Fill               string
	Alias              string
	TimeStartOperator  string
	TimeEndOperator    string
}

func (t *Time) AddTimeStart(timeStart int64) {
	if timeStart > t.TimeStart {
		t.TimeStart = timeStart
	}
}

func (t *Time) AddTimeEnd(timeEnd int64) {
	if t.TimeEnd == 0 || timeEnd < t.TimeEnd {
		t.TimeEnd = timeEnd
	}
}

func (t *Time) AddInterval(interval int) {
	t.Interval = interval
}

func (t *Time) AddWindowSize(windowSize int) {
	t.WindowSize = windowSize
}

func (t *Time) AddFill(fill string) {
	t.Fill = fill
}

func (t *Time) AddOffset(offset int) {
	t.Offset = offset
}

func (t *Time) AddAlias(alias string) {
	t.Alias = alias
}

func NewTime() *Time {
	return &Time{
		TimeEnd:            0,
		DatasourceInterval: 1,
		WindowSize:         1,
		TimeStartOperator:  ">=",
		TimeEndOperator:    "<=",
	}
}

type View struct {
	Model         *Model     //初始化view
	SubViewLevels []*SubView //由RawView拆层
	NoPreWhere    bool       // Whether to use prewhere
}

// 使用model初始化view
func NewView(m *Model) *View {
	return &View{Model: m}
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

func (v *View) GetCallbacks() (callbacks map[string]func(*common.Result) error) {
	return v.Model.Callbacks
}

func (v *View) trans() {
	var tagsLevelInner []Node
	var tagsLevelMetrics []Node
	var tagsLevelTop []Node
	var metricsLevelInner []Node
	var metricsLevelMetrics []Node
	var metricsLevelTop []Node
	var groupsLevelInner []Node
	var groupsLevelMetrics []Node
	var tagsAliasInner []string
	var groupsValueInner []string
	// 遍历tags，解析至分层结构中
	for _, tag := range v.Model.Tags.tags {
		switch node := tag.(type) {
		case *Tag:
			if node.Flag == NODE_FLAG_METRICS {
				// Tag在最内层中只保留value 去掉alias
				tagsLevelInner = append(tagsLevelInner, tag)
				// 外层tag
				metricTag := &Tag{}
				if node.Alias != "" {
					metricTag.Value = node.Alias
				} else {
					metricTag.Value = node.Value
				}
				tagsLevelMetrics = append(tagsLevelMetrics, metricTag)
				tagsAliasInner = append(tagsAliasInner, metricTag.Value)
			} else if node.Flag == NODE_FLAG_METRICS_INNER {
				metricsLevelInner = append(metricsLevelInner, tag)
				tagsAliasInner = append(tagsAliasInner, node.Alias)
			} else if node.Flag == NODE_FLAG_METRICS_OUTER {
				metricsLevelMetrics = append(metricsLevelMetrics, tag)
			} else if node.Flag == NODE_FLAG_METRICS_TOP {
				tagsLevelTop = append(tagsLevelTop, tag)
			}
		case Function:
			flag := node.GetFlag()
			node.SetTime(v.Model.Time)
			node.Init()
			if flag == METRICS_FLAG_INNER {
				metricsLevelInner = append(metricsLevelInner, tag)
			} else if flag == METRICS_FLAG_OUTER {
				metricsLevelMetrics = append(metricsLevelMetrics, tag)
			} else if flag == METRICS_FLAG_TOP {
				metricsLevelTop = append(metricsLevelTop, tag)
			}
		}
	}
	// 存在类似histogram三层算子时，将newTag这种必须返回的Tag加入最外层
	if len(metricsLevelTop) > 0 {
		metricsLevelTop = append(metricsLevelTop, tagsLevelTop...)
	}
	// 计算层拆层的情况下，默认类型的group中with只放在最里层
	for _, node := range v.Model.Groups.groups {
		group := node.(*Group)
		if group.Flag == GROUP_FLAG_DEFAULT {
			groupsLevelInner = append(groupsLevelInner, group)
			// 外层group
			metricGroup := &Group{}
			if group.Alias != "" {
				metricGroup.Value = group.Alias
			} else {
				metricGroup.Value = group.Value
			}
			groupsLevelMetrics = append(groupsLevelMetrics, metricGroup)
			// 由于会出现字段在内层group中但不在内层tag中，但外层group也需要，因此内层tag会与group做并集
			groupsValueInner = append(groupsValueInner, metricGroup.Value)
		} else if group.Flag == GROUP_FLAG_METRICS_OUTER {
			groupsLevelMetrics = append(groupsLevelMetrics, group)
		} else if group.Flag == GROUP_FLAG_METRICS_INNTER {
			groupsLevelInner = append(groupsLevelInner, group)
		}
	}
	if v.Model.MetricsLevelFlag == MODEL_METRICS_LEVEL_FLAG_UNLAY {
		// 计算层不拆层
		// 里层tag+外层metric
		sv := SubView{
			Tags:       &Tags{tags: append(tagsLevelInner, metricsLevelMetrics...)},
			Groups:     v.Model.Groups,
			From:       v.Model.From,
			Filters:    v.Model.Filters,
			Havings:    v.Model.Havings,
			Orders:     v.Model.Orders,
			Limit:      v.Model.Limit,
			NoPreWhere: v.NoPreWhere,
		}
		v.SubViewLevels = append(v.SubViewLevels, &sv)
	} else if v.Model.MetricsLevelFlag == MODEL_METRICS_LEVEL_FLAG_LAYERED {
		// 里层的select需要包含所有里层group
		for _, group := range groupsValueInner {
			if !common.IsValueInSliceString(group, tagsAliasInner) {
				tagsLevelInner = append(tagsLevelInner, &Tag{Value: group})
			}
		}
		// 计算层需要拆层
		// 计算层里层
		svInner := SubView{
			Tags:       &Tags{tags: append(tagsLevelInner, metricsLevelInner...)}, // 计算层所有tag及里层算子
			Groups:     &Groups{groups: groupsLevelInner},                         // group分层
			From:       v.Model.From,                                              // 查询表
			Filters:    v.Model.Filters,                                           // 所有filter
			Havings:    &Filters{},
			Orders:     &Orders{},
			Limit:      &Limit{},
			NoPreWhere: v.NoPreWhere,
		}
		v.SubViewLevels = append(v.SubViewLevels, &svInner)
		// 计算层外层
		svMetrics := SubView{
			Tags:       &Tags{tags: append(tagsLevelMetrics, metricsLevelMetrics...)}, // 计算层所有tag及外层算子
			Groups:     &Groups{groups: groupsLevelMetrics},                           // group分层
			From:       &Tables{},                                                     // 空table
			Filters:    &Filters{},                                                    // 空filter
			Havings:    v.Model.Havings,
			Orders:     v.Model.Orders,
			Limit:      v.Model.Limit,
			NoPreWhere: v.NoPreWhere,
		}
		v.SubViewLevels = append(v.SubViewLevels, &svMetrics)
	}
	if metricsLevelTop != nil {
		// 顶层，只保留指定tag，比如histogram
		svOuter := SubView{
			Tags:       &Tags{tags: metricsLevelTop}, // 所有翻译层tag
			Groups:     &Groups{},                    // 空group
			From:       &Tables{},                    // 空table
			Filters:    &Filters{},                   //空filter
			Havings:    &Filters{},
			Orders:     &Orders{},
			Limit:      &Limit{},
			NoPreWhere: v.NoPreWhere,
		}
		v.SubViewLevels = append(v.SubViewLevels, &svOuter)
	}
}

type SubView struct {
	Tags       *Tags
	Filters    *Filters
	From       *Tables
	Groups     *Groups
	Orders     *Orders
	Limit      *Limit
	Havings    *Filters
	NoPreWhere bool
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
	if nodeWiths := sv.Havings.GetWiths(); nodeWiths != nil {
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
			tmpMap[str] = nil
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
		buf.WriteString(" ")
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
		from := sv.From.ToString()
		if strings.HasPrefix(from, "flow_tag") {
			buf.WriteString(" WHERE ")
		} else if strings.HasPrefix(from, "flow_metrics") && !strings.HasSuffix(from, ".1m`") && !strings.HasSuffix(from, ".1s`") {
			buf.WriteString(" WHERE ")
		} else if !sv.NoPreWhere {
			buf.WriteString(" PREWHERE ")
		} else {
			buf.WriteString(" WHERE ")
		}
		sv.Filters.WriteTo(buf)
	}
	if !sv.Groups.IsNull() {
		sv.Groups.groups = sv.removeDup(sv.Groups)
		buf.WriteString(" GROUP BY ")
		sv.Groups.WriteTo(buf)
	}
	if !sv.Havings.IsNull() {
		buf.WriteString(" HAVING ")
		sv.Havings.WriteTo(buf)
	}
	if !sv.Orders.IsNull() {
		buf.WriteString(" ORDER BY ")
		sv.Orders.WriteTo(buf)
	}
	sv.Limit.WriteTo(buf)
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
