package engine

import (
	"github.com/akito0107/xsqlparser/sqlast"
)

type Engine interface {
	TransSelect([]sqlast.SQLSelectItem) error
	TransFrom([]sqlast.TableReference) error
	TransGroupBy([]sqlast.Node) error
	TransWhere(sqlast.Node) error
	ToSQLString() string
	Init()
	ExecuteQuery(string) ([]string, error)
}
