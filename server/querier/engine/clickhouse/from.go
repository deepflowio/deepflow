package clickhouse

import (
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/view"
)

type Table struct {
	Value string
}

func (t *Table) Format(m *view.Model) {
	m.AddTable(t.Value)
}
