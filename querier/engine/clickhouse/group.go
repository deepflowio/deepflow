package clickhouse

import (
	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

func GetGroup(name string, asTagMap map[string]string, db, table string) (Statement, error) {
	if asTagMap[name] == "time" {
		return nil, nil
	}
	tag, ok := tag.GetTag(name, db, table, "default")
	if ok {
		if tag.TagTranslator != "" {
			stmt := &GroupTag{Value: tag.TagTranslator, Alias: name}
			return stmt, nil
		} else {
			stmt := &GroupTag{Value: name}
			return stmt, nil
		}
	} else {
		stmt := &GroupTag{Value: name}
		return stmt, nil
	}
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
}
