package clickhouse

import (
	"metaflow/querier/engine/clickhouse/view"
)

// TODO: 按需修改并做抽象
func GetGroup(group string) Statement {
	var stmt Statement
	// 根据group字段返回具体group单元结构体
	switch group {
	case "host":
		stmt = &GroupHost{}
	default:
		stmt = &GroupDefault{Value: group}
	}
	return stmt
}

type GroupDefault struct {
	Value string
}

func (g *GroupDefault) Format(m *view.Model) {
	m.AddGroup(&view.Group{Value: g.Value})
}

// 仅示例
type GroupHost struct{}

func (g *GroupHost) Format(m *view.Model) {
	// TODO: group常量结构替换&Flag常量结构替换
	m.AddGroup(&view.Group{Value: "host_id"})
}
