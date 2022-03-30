package clickhouse

import (
	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

func GetGroup(name string, asTagMap map[string]string) (Statement, error) {
	if asTagMap[name] == "time" {
		return nil, nil
	}
	stmt := &GroupTag{Value: name}
	return stmt, nil
}

func GetNotNullFilter(name string, asTagMap map[string]string, db, table string) (view.Node, bool) {
	tagItem, ok := tag.GetTag(name, db, table)
	if !ok {
		preAsTag, ok := asTagMap[name]
		if ok {
			tagItem, ok = tag.GetTag(preAsTag, db, table)
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
	Withs []view.Node
}

func (g *GroupTag) Format(m *view.Model) {
	m.AddGroup(&view.Group{Value: g.Value, Withs: g.Withs})
}
