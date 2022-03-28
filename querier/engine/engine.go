package engine

import (
	"github.com/xwb1989/sqlparser"
)

type Engine interface {
	TransSelect(sqlparser.SelectExprs) error
	TransFrom(sqlparser.TableExprs) error
	TransGroupBy(sqlparser.GroupBy) error
	TransWhere(*sqlparser.Where) error
	TransHaving(*sqlparser.Where) error
	TransOrderBy(sqlparser.OrderBy) error
	TransLimit(*sqlparser.Limit) error
	ToSQLString() string
	Init()
	ExecuteQuery(string) (map[string][]interface{}, error)
}
