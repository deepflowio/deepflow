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
	for _, tag := range pStmt.Projection {
		err := p.parseSelect(tag)
		if err != nil {
			return err
		}
	}
	// From解析
	for _, from := range pStmt.FromClause {
		err := p.parseFrom(from)
		if err != nil {
			return err
		}
	}
	// GroupBy解析
	for _, group := range pStmt.GroupByClause {
		err := p.parseGroupBy(group)
		if err != nil {
			return err
		}
	}
	return nil
}

// 解析From
func (p *Parser) parseFrom(from sqlast.TableReference) error {
	switch from := from.(type) {
	case *sqlast.Table:
		// 解析Table类型
		p.Engine.AddTable(p.parseIdent(from.Name.Idents[0]))
	}
	return nil
}

// 解析GroupBy
func (p *Parser) parseGroupBy(group sqlast.Node) error {
	p.Engine.AddGroup(p.parseIdent(group.(*sqlast.Ident)))
	return nil
}

// 解析Select
func (p *Parser) parseSelect(tag sqlast.SQLSelectItem) error {
	// 解析select内容
	switch tag := tag.(type) {
	// 带as
	case *sqlast.AliasSelectItem:
		return p.parseSelectAlias(tag)
	// 不带as
	case *sqlast.UnnamedSelectItem:
		return p.parseSelectUnalias(tag)
	}
	return nil
}

// 解析select内容中不带as的格式
func (p *Parser) parseSelectUnalias(item *sqlast.UnnamedSelectItem) error {
	//var args []string
	switch node := item.Node.(type) {
	case *sqlast.Ident:
		p.Engine.AddTag(p.parseIdent(node), "")
	}
	return nil
}

// 解析select内容中带as的格式
func (p *Parser) parseSelectAlias(item *sqlast.AliasSelectItem) error {
	as := item.Alias.ToSQLString()
	//var args []string
	switch expr := item.Expr.(type) {
	// 普通字符串
	case *sqlast.Ident:
		p.Engine.AddTag(p.parseIdent(expr), as)
	// func(field)
	case *sqlast.Function:
	// field +=*/ field
	case *sqlast.BinaryExpr:
	}
	return nil
}

func (p *Parser) parseIdent(item *sqlast.Ident) string {
	return item.ToSQLString()
}
