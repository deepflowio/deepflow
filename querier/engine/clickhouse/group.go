package clickhouse

import (
	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

func GetGroup(name string) ([]Statement, error) {
	var stmts []Statement
	tag, err := tag.GetTag(name)
	if err != nil {
		return stmts, err
	}
	for _, tagGeneratorName := range tag.TagGeneratorName {
		if tagGeneratorName != "" {
			stmts = append(stmts, &GroupTag{Value: tagGeneratorName})
		}
	}
	return stmts, nil
}

type GroupTag struct {
	Value string
	Withs []view.Node
}

func (g *GroupTag) Format(m *view.Model) {
	m.AddGroup(&view.Group{Value: g.Value, Withs: g.Withs})
}
