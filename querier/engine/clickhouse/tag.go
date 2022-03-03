package clickhouse

import (
	"metaflow/querier/engine/clickhouse/view"
)

type TagDefault struct {
	Value string
	Alias string
}

func (t *TagDefault) Format(m *view.Model) {
	m.AddTag(t.Value, t.Alias, 0)
}

type TagHost struct {
	Alias string
}

func (t *TagHost) Format(m *view.Model) {
	// TODO: tag常量结构替换&Flag常量结构替换
	if t.Alias == "" {
		t.Alias = "host"
	}
	m.AddTag("host_id", t.Alias, 0)
}
