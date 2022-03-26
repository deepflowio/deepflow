package engine

import (
	"github.com/xwb1989/sqlparser"
)

type Engine interface {
	TransSelect(sqlparser.SelectExprs) (map[string]string, error)
	TransFrom(sqlparser.TableExprs) error
	TransGroupBy(sqlparser.GroupBy, map[string]string) error
	TransWhere(*sqlparser.Where, map[string]string) error
	TransOrderBy(sqlparser.OrderBy) error
	TransLimit(*sqlparser.Limit) error
	ToSQLString() string
	Init()
	ExecuteQuery(string) (map[string][]interface{}, error)
}
