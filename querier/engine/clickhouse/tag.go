package clickhouse

import (
	"fmt"

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
		for _, suffix := range []string{"", "_0", "_1"} {
			ip4Suffix := "ip4" + suffix
			ip6Suffix := "ip6" + suffix
			for _, resource := range []string{"resource_gl0_id", "resource_gl1_id", "resource_gl2_id"} {
				if name == resource+suffix {
					ipTag := fmt.Sprintf("multiIf(%s=0 and is_ipv4=1,IPv4NumToString(%s), %s=0 and is_ipv4=0,IPv6NumToString(%s),%s!=0 and is_ipv4=1,'0.0.0.0','::')", name, ip4Suffix, name, ip6Suffix, name)
					subnetTag := "subnet_id" + suffix
					ipStmt := &SelectTag{Value: ipTag, Alias: "ip" + suffix}
					subnetStmt := &SelectTag{Value: subnetTag}
					stmts = append(stmts, ipStmt)
					stmts = append(stmts, subnetStmt)
				}
			}
			for _, resourceName := range []string{"resource_gl0", "resource_gl1", "resource_gl2"} {
				resourceIDSuffix := resourceName + "_id" + suffix
				if name == resourceName+suffix {
					ipTag := fmt.Sprintf("multiIf(%s=0 and is_ipv4=1,IPv4NumToString(%s), %s=0 and is_ipv4=0,IPv6NumToString(%s),%s!=0 and is_ipv4=1,'0.0.0.0','::')", resourceIDSuffix, ip4Suffix, resourceIDSuffix, ip6Suffix, resourceIDSuffix)
					subnetTag := "subnet_id" + suffix
					ipStmt := &SelectTag{Value: ipTag, Alias: "ip" + suffix}
					subnetStmt := &SelectTag{Value: subnetTag}
					stmts = append(stmts, ipStmt)
					stmts = append(stmts, subnetStmt)
				}
			}
		}
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
