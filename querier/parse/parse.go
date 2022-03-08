package parse

import (
	"bytes"
	"github.com/akito0107/xsqlparser"
	"github.com/akito0107/xsqlparser/dialect"
	"github.com/akito0107/xsqlparser/sqlast"
	"metaflow/querier/engine"
)

type Parser struct {
	Engine engine.Engine
}

func NewParser() *Parser {
	return &Parser{}
}

// 解析入口，解析结果写入Model
func (p *Parser) ParseSQL(sql string) error {
	// sql解析
	parser, err := xsqlparser.NewParser(bytes.NewBufferString(sql), &dialect.GenericSQLDialect{})
	if err != nil {
		return err
	}
	Stmt, err := parser.ParseStatement()
	if err != nil {
		return err
	}

	pStmt := Stmt.(*sqlast.QueryStmt).Body.(*sqlast.SQLSelect)
	// Select解析
	selectErr := p.Engine.TransSelect(pStmt.Projection)
	if selectErr != nil {
		return selectErr
	}
	// From解析
	fromErr := p.Engine.TransFrom(pStmt.FromClause)
	if fromErr != nil {
		return fromErr
	}
	// Where 解析
	whereErr := p.Engine.TransWhere(pStmt.WhereClause)
	if whereErr != nil {
		return whereErr
	}
	// GroupBy解析
	groupErr := p.Engine.TransGroupBy(pStmt.GroupByClause)
	if groupErr != nil {
		return groupErr
	}

	return nil
}
