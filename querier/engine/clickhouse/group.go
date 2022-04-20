package clickhouse

import (
	"fmt"
	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

func GetGroup(name string, asTagMap map[string]string, db, table string) (Statement, error) {
	if asTagMap[name] == "time" {
		return nil, nil
	}
	var stmt Statement
	tag, ok := tag.GetTag(name, db, table, "default")
	if ok {
		if tag.TagTranslator != "" {
			stmt = &GroupTag{Value: tag.TagTranslator, Alias: name}
		} else {
			stmt = &GroupTag{Value: name}
		}
	} else {
		stmt = &GroupTag{Value: name}
	}
	return stmt, nil
}

func GetNotNullFilter(name string, asTagMap map[string]string, db, table string) (view.Node, bool) {
	tagItem, ok := tag.GetTag(name, db, table, "default")
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
	for _, suffix := range []string{"", "_0", "_1"} {
		ip4Suffix := "ip4" + suffix
		ip6Suffix := "ip6" + suffix
		for _, resourceName := range []string{"resource_gl0", "resource_gl1", "resource_gl2"} {
			resourceIDSuffix := resourceName + "_id" + suffix
			resourceTypeSuffix := resourceName + "_type" + suffix
			if g.Alias == resourceName+suffix {
				ipTag := fmt.Sprintf("multiIf(%s=0 and is_ipv4=1,IPv4NumToString(%s), %s=0 and is_ipv4=0,IPv6NumToString(%s),%s!=0 and is_ipv4=1,'0.0.0.0','::')", resourceIDSuffix, ip4Suffix, resourceIDSuffix, ip6Suffix, resourceIDSuffix)
				subnetIDSuffix := "subnet_id" + suffix
				subnetTag := fmt.Sprintf("if(%s=0,%s,0)", resourceIDSuffix, subnetIDSuffix)
				m.AddTag(&view.Tag{Value: ipTag, Alias: "ip" + suffix})
				m.AddTag(&view.Tag{Value: subnetTag, Alias: subnetIDSuffix})
				m.AddGroup(&view.Group{Value: "ip" + suffix})
				m.AddGroup(&view.Group{Value: subnetIDSuffix})
				m.AddGroup(&view.Group{Value: resourceTypeSuffix})
			}
		}
	}
}
