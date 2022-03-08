package clickhouse

import (
	"fmt"
	"github.com/akito0107/xsqlparser/sqlast"
	"metaflow/querier/engine/clickhouse/view"
)

type Where struct {
	filter *view.Filters
	withs  []*view.With
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
	Trans(sqlast.Node, *Where) view.Node
}

type WhereDefault struct{}

func (t *WhereDefault) Trans(expr sqlast.Node, stmt *Where) view.Node {
	return &view.Expr{Value: expr.ToSQLString()}
}

// 仅示例
type WhereHost struct{}

func (t *WhereHost) Trans(expr sqlast.Node, stmt *Where) view.Node {
	switch expr.(*sqlast.BinaryExpr).Op.Type {
	case sqlast.Eq:
		sql := fmt.Sprintf("%s %s %s", "host_id", "=", "1")
		return &view.Expr{Value: sql}
	}
	return nil
}
