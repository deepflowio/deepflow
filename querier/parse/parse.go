package parse

import (
	"github.com/xwb1989/sqlparser"
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
	stmt, err := sqlparser.Parse(sql)
	if err != nil {
		return err
	}

	pStmt := stmt.(*sqlparser.Select)
	// From解析
	if pStmt.From != nil {
		fromErr := p.Engine.TransFrom(pStmt.From)
		if fromErr != nil {
			return fromErr
		}
	}

	// Select解析
	if pStmt.SelectExprs != nil {
		selectErr := p.Engine.TransSelect(pStmt.SelectExprs)
		if selectErr != nil {
			return selectErr
		}
	}

	// Where 解析
	if pStmt.Where != nil {
		whereErr := p.Engine.TransWhere(pStmt.Where)
		if whereErr != nil {
			return whereErr
		}
	}

	// GroupBy解析
	if pStmt.GroupBy != nil {
		groupErr := p.Engine.TransGroupBy(pStmt.GroupBy)
		if groupErr != nil {
			return groupErr
		}

	}
	return nil
}
