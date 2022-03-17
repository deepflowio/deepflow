package clickhouse

import (
	"fmt"
	"strings"

	"github.com/xwb1989/sqlparser"

	"metaflow/querier/engine/clickhouse/view"
	"metaflow/querier/tag"
)

type Where struct {
	filter *view.Filters
	withs  []view.Node
}

func (w *Where) Format(m *view.Model) {
	w.filter.Withs = w.withs
	if !w.filter.IsNull() {
		m.AddFilter(w.filter)
	}
}

// TODO: 按需修改并做抽象
func GetWhere(name, value string) WhereStatement {
	var stmt WhereStatement
	stmt = &WhereTag{Tag: name, Value: value}
	return stmt
}

type WhereStatement interface {
	Trans(sqlparser.Expr) (view.Node, error)
}

type WhereTag struct {
	Tag   string
	Value string
}

func (t *WhereTag) Trans(expr sqlparser.Expr) (view.Node, error) {
	op := expr.(*sqlparser.ComparisonExpr).Operator
	tag, err := tag.GetTag(t.Tag)
	if err != nil {
		return nil, err
	}
	filterSlice := []string{}
	notNullFilter := tag.NotNullFilter
	if notNullFilter != "" {
		filterSlice = append(filterSlice, notNullFilter)
	}
	whereFilter := tag.WhereTranslator
	if whereFilter != "" {
		whereFilter = fmt.Sprintf(tag.WhereTranslator, op, t.Value)
		filterSlice = append(filterSlice, whereFilter)
	}
	filter := strings.Join(filterSlice, " AND ")
	return &view.Expr{Value: filter}, nil
}
