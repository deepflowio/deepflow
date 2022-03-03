package clickhouse

import (
	"metaflow/querier/engine/clickhouse/view"
)

type GroupDefault struct {
	Value string
}

func (g *GroupDefault) Format(m *view.Model) {
	m.AddGroup(g.Value, 0)
}

type GroupHost struct{}

func (g *GroupHost) Format(m *view.Model) {
	// TODO: group常量结构替换&Flag常量结构替换
	m.AddGroup("host_id", 0)
}
