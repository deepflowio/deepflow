package clickhouse

import (
	"strings"

	"github.com/k0kubun/pp"
	"github.com/xwb1989/sqlparser"

	"metaflow/querier/engine/clickhouse/client"
	"metaflow/querier/engine/clickhouse/metric"
	"metaflow/querier/engine/clickhouse/view"
	"metaflow/querier/parse"
	"metaflow/querier/tag/description"
)

type CHEngine struct {
	Model      *view.Model
	IP         string
	Statements []Statement
	DB         string
	Table      string
}

func (e *CHEngine) ExecuteQuery(sql string) (map[string][]interface{}, error) {
	// 解析show开头的sql
	// show metrics/tags from <table_name> 例：show metrics/tags from l4_flow_log
	result, isShow, err := e.ParseShowSql(sql)
	if isShow {
		if err != nil {
			return nil, err
		}
		return result, nil
	}

	parser := parse.Parser{Engine: e}
	err = parser.ParseSQL(sql)
	if err != nil {
		return nil, err
	}
	chSql := e.ToSQLString()
	pp.Println(chSql)
	// TODO: 根据config写入
	chClient := client.Client{
		IP:       e.IP,
		Port:     "9000",
		UserName: "default",
		Password: "",
		DB:       e.DB,
	}
	err = chClient.Init()
	if err != nil {
		return nil, err
	}
	rst, err := chClient.DoQuery(chSql)
	pp.Println(rst)
	return rst, err
}

func (e *CHEngine) Init() {
	e.Model = view.NewModel()
}

func (e *CHEngine) ParseShowSql(sql string) (map[string][]interface{}, bool, error) {
	sqlSplit := strings.Split(sql, " ")
	if strings.ToLower(sqlSplit[0]) != "show" {
		return nil, false, nil
	}
	var table string
	for i, item := range sqlSplit {
		if strings.ToLower(item) == "from" {
			table = sqlSplit[i+1]
			break
		}
	}
	switch strings.ToLower(sqlSplit[1]) {
	case "metric":
		if strings.ToLower(sqlSplit[2]) == "functions" {
			funcs, err := metric.GetFunctionDescriptions()
			return funcs, true, err
		} else {
			// TODO: 解析失败
			return nil, true, nil
		}
	case "metrics":
		metrics, err := metric.GetMetricDescriptions(e.DB, table)
		return metrics, true, err
	case "tags":
		data := description.GetTagDescriptions(e.DB, table)
		return data, true, nil
	default:
		// TODO: 解析失败
		return nil, true, nil
	}
}

func (e *CHEngine) TransSelect(tags sqlparser.SelectExprs) error {
	for _, tag := range tags {
		err := e.parseSelect(tag)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *CHEngine) TransWhere(node *sqlparser.Where) error {
	// 生成where的statement
	whereStmt := Where{}
	// 解析ast树并生成view.Node结构
	expr, err := parseWhere(node.Expr, &whereStmt)
	filter := view.Filters{Expr: expr}
	whereStmt.filter = &filter
	e.Statements = append(e.Statements, &whereStmt)
	return err
}

func (e *CHEngine) TransFrom(froms sqlparser.TableExprs) error {
	for _, from := range froms {
		switch from := from.(type) {
		case *sqlparser.AliasedTableExpr:
			// 解析Table类型
			table := sqlparser.String(from)
			e.AddTable(table)
			e.Table = table
		}

	}
	return nil
}

func (e *CHEngine) TransGroupBy(groups sqlparser.GroupBy) error {
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
	for _, stmt := range e.Statements {
		stmt.Format(e.Model)
	}
	// 使用Model生成View
	chView := view.NewView(e.Model)
	// View生成clickhouse-sql
	chSql := chView.ToString()
	return chSql
}

// 解析GroupBy
func (e *CHEngine) parseGroupBy(group sqlparser.Expr) error {
	//var args []string
	switch expr := group.(type) {
	// 普通字符串
	case *sqlparser.ColName:
		e.AddGroup(sqlparser.String(expr))
	// func(field)
	case *sqlparser.FuncExpr:
		/* name, args, err := e.parseFunction(expr)
		if err != nil {
			return err
		}
		err = e.AddFunction(name, args, "", as)
		return err */
	// field +=*/ field
	case *sqlparser.BinaryExpr:
		/* function := expr.Left.(*sqlparser.FuncExpr)
		name, args, err := e.parseFunction(function)
		if err != nil {
			return err
		}
		math := expr.Operator
		math += sqlparser.String(expr.Right)
		e.AddFunction(name, args, math, as) */
	}
	return nil
}

// 解析Select
func (e *CHEngine) parseSelect(tag sqlparser.SelectExpr) error {
	// 解析select内容
	switch tag := tag.(type) {
	// 带as
	case *sqlparser.AliasedExpr:
		return e.parseSelectAlias(tag)
	}
	return nil
}

func (e *CHEngine) parseSelectAlias(item *sqlparser.AliasedExpr) error {
	as := sqlparser.String(item.As)
	//var args []string
	switch expr := item.Expr.(type) {
	// 普通字符串
	case *sqlparser.ColName:
		e.AddTag(sqlparser.String(expr), as)
	// func(field)
	case *sqlparser.FuncExpr:
		name, args, err := e.parseFunction(expr)
		if err != nil {
			return err
		}
		err = e.AddFunction(name, args, "", as)
		return err
	// field +=*/ field
	case *sqlparser.BinaryExpr:
		function := expr.Left.(*sqlparser.FuncExpr)
		name, args, err := e.parseFunction(function)
		if err != nil {
			return err
		}
		math := expr.Operator
		math += sqlparser.String(expr.Right)
		e.AddFunction(name, args, math, as)
	}
	return nil
}

func (e *CHEngine) parseFunction(item *sqlparser.FuncExpr) (name string, args []string, err error) {
	for _, arg := range item.Exprs {
		args = append(args, sqlparser.String(arg))
	}
	return sqlparser.String(item.Name), args, nil
}

func (e *CHEngine) AddGroup(group string) {
	stmt := GetGroup(group)
	e.Statements = append(e.Statements, stmt)
}

func (e *CHEngine) AddTable(table string) {
	stmt := &Table{Value: table}
	e.Statements = append(e.Statements, stmt)
}

func (e *CHEngine) AddTag(tag string, alias string) {
	stmt := GetTag(tag, alias)
	e.Statements = append(e.Statements, stmt)
}

func (e *CHEngine) AddFunction(name string, args []string, math string, alias string) error {
	function, levelFlag, err := GetFunc(name, args, math, alias, e.DB, e.Table)
	if err != nil {
		return err
	}
	// 通过metric判断view是否拆层
	e.SetLevelFlag(levelFlag)
	e.Statements = append(e.Statements, function)
	return nil
}

func (e *CHEngine) SetLevelFlag(flag int) {
	if flag > e.Model.MetricLevelFlag {
		e.Model.MetricLevelFlag = flag
	}
}

func parseWhere(node sqlparser.Expr, w *Where) (view.Node, error) {
	switch node := node.(type) {
	case *sqlparser.AndExpr:
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
	case *sqlparser.OrExpr:
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
	case *sqlparser.NotExpr:
		expr, err := parseWhere(node.Expr, w)
		if err != nil {
			return expr, err
		}
		op := view.Operator{Type: view.NOT}
		return &view.UnaryExpr{Op: op, Expr: expr}, nil
	case *sqlparser.ParenExpr: // 括号
		expr, err := parseWhere(node.Expr, w)
		if err != nil {
			return expr, err
		}
		return &view.Nested{Expr: expr}, nil
	case *sqlparser.ComparisonExpr:
		whereTag := sqlparser.String(node.Left)
		stmt := GetWhere(whereTag)
		return stmt.Trans(node, w), nil
	}
	return nil, nil
}

// 翻译单元,翻译结果写入view.Model
type Statement interface {
	Format(*view.Model)
}
