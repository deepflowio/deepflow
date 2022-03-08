package clickhouse

import (
	"metaflow/querier/engine/clickhouse/view"
)

func GetTag(tag string, alias string) Statement {
	var stmt Statement
	// 根据tag字段返回具体tag单元结构体
	switch tag {
	// TODO: tag常量结构替换&Flag常量结构替换
	case "host":
		stmt = &TagHost{Alias: alias}
	default:
		stmt = &TagDefault{Value: tag, Alias: alias}
	}
	return stmt
}

type TagDefault struct {
	Value string
	Alias string
}

func (t *TagDefault) Format(m *view.Model) {
	m.AddTag(&view.Tag{Value: t.Value, Alias: t.Alias})
}

type TagHost struct {
	Alias string
}

func (t *TagHost) Format(m *view.Model) {
	// TODO: tag常量结构替换&Flag常量结构替换
	if t.Alias == "" {
		t.Alias = "host"
	}
	m.AddTag(&view.Tag{Value: "host_id", Alias: t.Alias})
}
