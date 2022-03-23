package clickhouse

import (
	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
)

func GetTagGenerator(name string, alias string) ([]Statement, error) {
	var stmts []Statement
	tag, err := tag.GetTag(name)
	if err != nil {
		return stmts, err
	}
	for index, tagGeneratorName := range tag.TagGeneratorName {
		withCondition := []view.Node{}
		if tag.TagGenerator[index] != "" {
			withCondition = []view.Node{&view.With{Value: tag.TagGenerator[index]}}
		}
		if tagGeneratorName != "" {
			stmts = append(stmts, &SelectTag{Value: tagGeneratorName, Withs: withCondition})
		}
	}
	return stmts, nil
}

func GetTagTranslator(name string, alias string) (Statement, error) {
	var stmt Statement
	tag, err := tag.GetTag(name)
	if err != nil {
		return stmt, err
	}
	if tag.TagTranslator != "" {
		withs := []view.Node{&view.With{Value: tag.TagTranslator}}
		stmt = &SelectTag{Value: name, Flag: view.NODE_FLAG_TRANS, Withs: withs}
	}
	return stmt, nil
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
