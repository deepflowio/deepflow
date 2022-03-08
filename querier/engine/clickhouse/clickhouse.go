package clickhouse

import (
	"github.com/akito0107/xsqlparser/sqlast"
	"metaflow/querier/engine/clickhouse/view"
	"metaflow/querier/parse"
)

type CHEngine struct {
	Model *view.Model
	IP    string
}

// 翻译单元,翻译结果写入view.Model
type Statement interface {
	Format(*view.Model)
}

func (e *CHEngine) Init() {
	e.Model = view.NewModel()
}

func (e *CHEngine) TransSelect(tags []sqlast.SQLSelectItem) error {
	for _, tag := range tags {
		err := e.parseSelect(tag)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *CHEngine) TransWhere(node sqlast.Node) error {
	// 生成where的statement
	whereStmt := Where{}
	// 解析ast树并生成view.Node结构
	expr, err := parseWhere(node, &whereStmt)
	filter := view.Filters{Expr: expr}
	whereStmt.filter = &filter
	// statement将结果写入model
	whereStmt.Format(e.Model)
	return err
}

func (e *CHEngine) TransFrom(froms []sqlast.TableReference) error {
	for _, from := range froms {
		switch from := from.(type) {
		case *sqlast.Table:
			// 解析Table类型
			e.AddTable(parseIdent(from.Name.Idents[0]))
		}
	}
	return nil
}

func (e *CHEngine) TransGroupBy(groups []sqlast.Node) error {
	for _, group := range groups {
		err := e.parseGroupBy(group)
		if err != nil {
			return err
		}
	}
	return nil
}

// 原始sql转为clickhouse-sql
func (e *CHEngine) ToSQLString() string {
	// 使用Model生成View
	chView := view.NewView(e.Model)
	// View生成clickhouse-sql
	chSql := chView.ToString()
	return chSql
}

func (e *CHEngine) ExecuteQuery(sql string) ([]string, error) {
	parser := parse.Parser{Engine: e}
	parser.ParseSQL(sql)
	//chSql := e.ToSQLString()
	return nil, nil
}

// 解析GroupBy
func (e *CHEngine) parseGroupBy(group sqlast.Node) error {
	e.AddGroup(parseIdent(group.(*sqlast.Ident)))
	return nil
}

// 解析Select
func (e *CHEngine) parseSelect(tag sqlast.SQLSelectItem) error {
	// 解析select内容
	switch tag := tag.(type) {
	// 带as
	case *sqlast.AliasSelectItem:
		return e.parseSelectAlias(tag)
	// 不带as
	case *sqlast.UnnamedSelectItem:
		return e.parseSelectUnalias(tag)
	}
	return nil
}

// 解析select内容中不带as的格式
func (e *CHEngine) parseSelectUnalias(item *sqlast.UnnamedSelectItem) error {
	//var args []string
	switch node := item.Node.(type) {
	case *sqlast.Ident:
		e.AddTag(node.ToSQLString(), "")
	}
	return nil
}

// 解析select内容中带as的格式
func (e *CHEngine) parseSelectAlias(item *sqlast.AliasSelectItem) error {
	as := item.Alias.ToSQLString()
	//var args []string
	switch expr := item.Expr.(type) {
	// 普通字符串
	case *sqlast.Ident:
		e.AddTag(parseIdent(expr), as)
	// func(field)
	case *sqlast.Function:
		//e.AddMetric(expr.Name.ToSQLString())
	// field +=*/ field
	case *sqlast.BinaryExpr:
	}
	return nil
}

func (e *CHEngine) AddGroup(group string) {
	stmt := GetGroup(group)
	stmt.Format(e.Model)
}

func (e *CHEngine) AddTable(table string) {
	stmt := &Table{Value: table}
	stmt.Format(e.Model)
}

func (e *CHEngine) AddTag(tag string, alias string) {
	stmt := GetTag(tag, alias)
	stmt.Format(e.Model)
}

func parseWhere(node sqlast.Node, w *Where) (view.Node, error) {
	switch node := node.(type) {
	case *sqlast.BinaryExpr:
		switch node.Op.Type {
		case sqlast.And: // AND
			left, err := parseWhere(node.Left, w)
			if err != nil {
				return left, err
			}
			right, err := parseWhere(node.Right, w)
			if err != nil {
				return right, err
			}
			op := view.Operator{Type: view.AND}
			return &view.BinaryExpr{Left: left, Right: right, Op: op}, nil
		case sqlast.Or: // OR
			left, err := parseWhere(node.Left, w)
			if err != nil {
				return left, err
			}
			right, err := parseWhere(node.Right, w)
			if err != nil {
				return right, err
			}
			op := view.Operator{Type: view.OR}
			return &view.BinaryExpr{Left: left, Right: right, Op: op}, nil
		default: // host='aaa'
			whereTag := node.Left.ToSQLString()
			stmt := GetWhere(whereTag)
			return stmt.Trans(node, w), nil
		}
	case *sqlast.UnaryExpr:
		expr, err := parseWhere(node.Expr, w)
		if err != nil {
			return expr, err
		}
		switch node.Op.Type {
		case sqlast.Not: // Not
			op := view.Operator{Type: view.NOT}
			return &view.UnaryExpr{Op: op, Expr: expr}, nil
		}
	case *sqlast.Nested: // 括号
		expr, err := parseWhere(node.AST, w)
		if err != nil {
			return expr, err
		}
		return &view.Nested{Expr: expr}, nil
	}
	return nil, nil
}

func parseIdent(item *sqlast.Ident) string {
	return item.ToSQLString()
}
