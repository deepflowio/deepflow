package clickhouse

import (
	"metaflow/querier/engine/clickhouse/view"
	"metaflow/querier/tag"
)

func GetTagGenerator(name string, alias string) ([]Statement, error) {
	var stmts []Statement
	tag, err := tag.GetTag(name)
	if err != nil {
		return stmts, err
	}
	for index, tagGenerator := range tag.TagGenerator {
		withCondition := []view.Node{}
		if tagGenerator != "" {
			withCondition = []view.Node{&view.With{Value: tagGenerator}}
		}
		stmts = append(stmts, &SelectTag{Value: tag.TagGeneratorName[index], Withs: withCondition})
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
		stmt = &SelectTag{Value: tag.Name, Flag: view.NODE_FLAG_TRANS, Withs: withs}
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
