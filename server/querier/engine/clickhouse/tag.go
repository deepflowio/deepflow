package clickhouse

import (
	"fmt"
	"strings"

	"github.com/metaflowys/metaflow/server/querier/common"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/metrics"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/tag"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/view"
)

func GetTagTranslator(name, alias, db, table string) (Statement, error) {
	var stmt Statement
	selectTag := name
	if alias != "" {
		selectTag = alias
	}
	tagItem, ok := tag.GetTag(name, db, table, "default")
	if !ok {
		name := strings.Trim(name, "`")
		if strings.HasPrefix(name, "label.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("k8s_label_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("k8s_label_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("k8s_label", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "label.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
			stmt = &SelectTag{Value: TagTranslatorStr, Alias: selectTag}
		} else if strings.HasPrefix(name, "tag.") || strings.HasPrefix(name, "attribute.") {
			tagItem, ok = tag.GetTag("external_tag", db, table, "default")
			nameNoPreffix := strings.TrimPrefix(name, "tag.")
			nameNoPreffix = strings.TrimPrefix(nameNoPreffix, "attribute.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
			stmt = &SelectTag{Value: TagTranslatorStr, Alias: selectTag}
		}
	} else {
		if tagItem.TagTranslator != "" {
			stmt = &SelectTag{Value: tagItem.TagTranslator, Alias: selectTag}
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
