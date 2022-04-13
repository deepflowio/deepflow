package clickhouse

import (
	"fmt"

	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
	"strings"
)

func GetGroup(name string, asTagMap map[string]string, db, table string) ([]Statement, error) {
	if asTagMap[name] == "time" {
		return nil, nil
	}
	var stmts []Statement
	tag, ok := tag.GetTag(strings.Trim(name, "`"), db, table, "default")
	if ok {
		for _, suffix := range []string{"", "_0", "_1"} {
			ip4Suffix := "ip4" + suffix
			ip6Suffix := "ip6" + suffix
			for _, resourceName := range []string{"resource_gl0", "resource_gl1", "resource_gl2"} {
				resourceIDSuffix := resourceName + "_id" + suffix
				if name == resourceName+suffix {
					ipTag := fmt.Sprintf("multiIf(%s=0 and is_ipv4=1,IPv4NumToString(%s), %s=0 and is_ipv4=0,IPv6NumToString(%s),%s!=0 and is_ipv4=1,'0.0.0.0','::')", resourceIDSuffix, ip4Suffix, resourceIDSuffix, ip6Suffix, resourceIDSuffix)
					subnetTag := "subnet_id" + suffix
					ipStmt := &GroupTag{Value: ipTag, Alias: "ip" + suffix}
					subnetStmt := &GroupTag{Value: subnetTag}
					stmts = append(stmts, ipStmt)
					stmts = append(stmts, subnetStmt)
				}
			}
		}
		if tag.TagTranslator != "" {
			stmt := &GroupTag{Value: tag.TagTranslator, Alias: name}
			stmts = append(stmts, stmt)
		} else {
			stmt := &GroupTag{Value: name}
			stmts = append(stmts, stmt)
		}
	} else {
		stmt := &GroupTag{Value: name}
		stmts = append(stmts, stmt)
	}
	return stmts, nil
}

func GetNotNullFilter(name string, asTagMap map[string]string, db, table string) (view.Node, bool) {
	tagItem, ok := tag.GetTag(strings.Trim(name, "`"), db, table, "default")
	if !ok {
		preAsTag, ok := asTagMap[name]
		if ok {
			tagItem, ok = tag.GetTag(preAsTag, db, table, "default")
			if !ok {
				return &view.Expr{}, false
			}
			filter := tagItem.NotNullFilter
			if filter == "" {
				return &view.Expr{}, false
			}
			return &view.Expr{Value: filter}, true
		} else {
			return &view.Expr{}, false
		}
	}
	if tagItem.NotNullFilter == "" {
		return &view.Expr{}, false
	}
	filter := "(" + tagItem.NotNullFilter + ")"
	return &view.Expr{Value: filter}, true
}

type GroupTag struct {
	Value string
	Alias string
	Withs []view.Node
}

func (g *GroupTag) Format(m *view.Model) {
	if len(g.Withs) == 0 {
		m.AddGroup(&view.Group{Value: g.Value, Alias: g.Alias})
	} else {
		m.AddGroup(&view.Group{Value: g.Value, Withs: g.Withs})
	}
}
