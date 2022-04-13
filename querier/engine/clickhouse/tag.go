package clickhouse

import (
	"metaflow/querier/engine/clickhouse/metrics"
	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

func GetTagTranslator(name, alias, db, table string) ([]Statement, error) {
	var stmts []Statement
	selectTag := name
	if alias != "" {
		selectTag = alias
	}
	tag, ok := tag.GetTag(name, db, table, "default")
	if !ok {
		return stmts, nil
	} else {
		if tag.TagTranslator != "" {
			stmt := &SelectTag{Value: tag.TagTranslator, Alias: selectTag}
			stmts = append(stmts, stmt)
		} else if alias != "" {
			stmt := &SelectTag{Value: name, Alias: selectTag}
			stmts = append(stmts, stmt)
		} else {
			stmt := &SelectTag{Value: selectTag}
			stmts = append(stmts, stmt)
		}
	}
	return stmts, nil
}

func GetMetricsTag(name string, alias string, db string, table string) (Statement, error) {
	metricStruct, ok := metrics.GetMetrics(name, db, table)
	if !ok {
		return nil, nil
	}
	if alias == "" && metricStruct.DBField != name {
		alias = name
	}
	return &SelectTag{Value: metricStruct.DBField, Alias: alias}, nil
}

func GetDefaultTag(name string, alias string) Statement {
	return &SelectTag{Value: name, Alias: alias}
}

type SelectTag struct {
	Value string
	Alias string
	Flag  int
	Withs []view.Node
}

func (t *SelectTag) Format(m *view.Model) {
	m.AddTag(&view.Tag{Value: t.Value, Alias: t.Alias, Flag: t.Flag, Withs: t.Withs})
}
