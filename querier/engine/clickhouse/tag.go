package clickhouse

import (
	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse/metrics"
	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

func GetTagTranslator(name, alias, db, table string) (Statement, error) {
	var stmt Statement
	selectTag := name
	if alias != "" {
		selectTag = alias
	}
	tag, ok := tag.GetTag(name, db, table, "default")
	if !ok {
		return stmt, nil
	} else {
		if tag.TagTranslator != "" {
			stmt = &SelectTag{Value: tag.TagTranslator, Alias: selectTag}
		} else if alias != "" {
			stmt = &SelectTag{Value: name, Alias: selectTag}
		} else {
			stmt = &SelectTag{Value: selectTag}
		}
	}
	return stmt, nil
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
	if common.IsValueInSliceString(t.Value, []string{"tap_port", "mac_0", "mac_1", "tunnel_tx_mac_0", "tunnel_tx_mac_1", "tunnel_rx_mac_0", "tunnel_rx_mac_1"}) {
		alias := t.Value
		if t.Alias != "" {
			alias = t.Alias
		}
		m.AddCallback(MacTranslate([]interface{}{t.Value, alias}))
	}
}
