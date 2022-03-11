package clickhouse

import (
	"fmt"
	"github.com/xwb1989/sqlparser"
	"metaflow/querier/engine/clickhouse/view"
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
func GetWhere(tag string) WhereStatement {
	switch tag {
	case "host":
		return &WhereHost{}
	default:
		return &WhereDefault{}
	}
}

type WhereStatement interface {
	Trans(sqlparser.Expr, *Where) view.Node
}

type WhereDefault struct{}

func (t *WhereDefault) Trans(expr sqlparser.Expr, stmt *Where) view.Node {
	return &view.Expr{Value: sqlparser.String(expr)}
}

// 仅示例
type WhereHost struct{}

func (t *WhereHost) Trans(expr sqlparser.Expr, stmt *Where) view.Node {
	op := expr.(*sqlparser.ComparisonExpr).Operator
	sql := fmt.Sprintf("%s %s %s", "host_id", op, "1")
	return &view.Expr{Value: sql}
}
