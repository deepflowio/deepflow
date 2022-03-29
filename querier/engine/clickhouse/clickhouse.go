package clickhouse

import (
	"strings"

	"github.com/k0kubun/pp"
	logging "github.com/op/go-logging"
	"github.com/xwb1989/sqlparser"

	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse/client"
	"metaflow/querier/engine/clickhouse/metrics"
	tagdescription "metaflow/querier/engine/clickhouse/tag/description"
	"metaflow/querier/engine/clickhouse/view"
	"metaflow/querier/parse"
)

var log = logging.MustGetLogger("clickhouse")
var DB_TABLE_MAP = map[string][]string{
	"flow_log": []string{"l4_flow_log", "l7_flow_log"},
}

type CHEngine struct {
	Model      *view.Model
	IP         string
	Statements []Statement
	DB         string
	Table      string
	asTagMap   map[string]string
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
	log.Debug(chSql)
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
	case "metrics":
		if strings.ToLower(sqlSplit[2]) == "functions" {
			funcs, err := metrics.GetFunctionDescriptions()
			return funcs, true, err
		} else {
			metrics, err := metrics.GetMetricsDescriptions(e.DB, table)
			return metrics, true, err
		}
	case "tag":
		// show tag {tag} values from table
		if len(sqlSplit) != 6 {
			// TODO: 增加日志记录解析失败
			return nil, true, nil
		}
		if strings.ToLower(sqlSplit[3]) == "values" {
			values, err := tagdescription.GetTagValues(e.DB, table, sqlSplit[2])
			return values, true, err
		}
		// TODO: 增加日志记录解析失败
		return nil, true, nil
	case "tags":
		data, err := tagdescription.GetTagDescriptions(e.DB, table)
		return data, true, err
	case "tables":
		return GetTables(e.DB), true, nil
	case "databases":
		return GetDatabases(), true, nil
	default:
		// TODO: 解析失败
		return nil, true, nil
	}
}

func (e *CHEngine) TransSelect(tags sqlparser.SelectExprs) error {
	e.asTagMap = make(map[string]string)
	for _, tag := range tags {
		err := e.parseSelect(tag)
		if err != nil {
			return err
		}
		item, ok := tag.(*sqlparser.AliasedExpr)
		if ok {
			as := sqlparser.String(item.As)
			colName, ok := item.Expr.(*sqlparser.ColName)
			if ok {
				e.asTagMap[as] = sqlparser.String(colName)
			}
			function, ok := item.Expr.(*sqlparser.FuncExpr)
			if ok {
				e.asTagMap[as] = sqlparser.String(function.Name)
			}
		}
	}
	return nil
}

func (e *CHEngine) TransWhere(node *sqlparser.Where) error {
	// 生成where的statement
	whereStmt := Where{time: e.Model.Time}
	// 解析ast树并生成view.Node结构
	expr, err := e.parseWhere(node.Expr, &whereStmt)
	filter := view.Filters{Expr: expr}
	whereStmt.filter = &filter
	e.Statements = append(e.Statements, &whereStmt)
	return err
}

func (e *CHEngine) TransHaving(node *sqlparser.Where) error {
	// 生成having的statement
	havingStmt := Having{Where{}}
	// 解析ast树并生成view.Node结构
	expr, err := e.parseWhere(node.Expr, &havingStmt.Where)
	filter := view.Filters{Expr: expr}
	havingStmt.filter = &filter
	e.Statements = append(e.Statements, &havingStmt)
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

func (e *CHEngine) TransOrderBy(orders sqlparser.OrderBy) error {
	for _, order := range orders {
		err := e.parseOrderBy(order)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *CHEngine) TransLimit(limit *sqlparser.Limit) error {
	e.Model.Limit.Limit = sqlparser.String(limit.Rowcount)
	if limit.Offset != nil {
		e.Model.Limit.Offset = sqlparser.String(limit.Offset)
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

func (e *CHEngine) parseOrderBy(order *sqlparser.Order) error {
	e.Model.Orders.Append(
		&view.Order{
			SortBy:  sqlparser.String(order.Expr),
			OrderBy: order.Direction,
		},
	)
	return nil
}

// 解析GroupBy
func (e *CHEngine) parseGroupBy(group sqlparser.Expr) error {
	//var args []string
	switch expr := group.(type) {
	// 普通字符串
	case *sqlparser.ColName:
		err := e.AddGroup(sqlparser.String(expr))
		if err != nil {
			return err
		}
		// TODO: 特殊处理塞进group的fromat中
		whereStmt := Where{}
		notNullExpr, ok := GetNotNullFilter(sqlparser.String(expr), e.asTagMap)
		if !ok {
			return nil
		}
		filter := view.Filters{Expr: notNullExpr}
		whereStmt.filter = &filter
		e.Statements = append(e.Statements, &whereStmt)
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
		err := e.AddTag(sqlparser.String(expr), as)
		if err != nil {
			return err
		}
	// func(field/tag)
	case *sqlparser.FuncExpr:
		name, args, err := e.parseFunction(expr)
		if err != nil {
			return err
		}
		name = strings.ReplaceAll(name, "`", "")
		if common.IsValueInSliceString(name, TAG_FUNCTIONS) {
			err := e.AddTagFunction(name, args, as)
			if err != nil {
				return err
			}
		} else {
			err = e.AddFunction(name, args, as)
		}
		return err
	// field +=*/ field 运算符
	case *sqlparser.BinaryExpr:
		binFunction, err := e.parseSelectBinaryExpr(expr)
		binFunction.SetAlias(as)
		e.Statements = append(e.Statements, binFunction)
		return err
	default:
		// TODO 报错
		return nil
	}
	return nil
}

func (e *CHEngine) parseFunction(item *sqlparser.FuncExpr) (name string, args []string, err error) {
	for _, arg := range item.Exprs {
		args = append(args, sqlparser.String(arg))
	}
	return sqlparser.String(item.Name), args, nil
}

// 解析运算符
func (e *CHEngine) parseSelectBinaryExpr(node sqlparser.Expr) (binary Function, err error) {
	switch expr := node.(type) {
	case *sqlparser.BinaryExpr:
		if !common.IsValueInSliceString(expr.Operator, view.MATH_FUNCTIONS) {
			// TODO: 报错 不支持的math
			return nil, nil
		}
		left, err := e.parseSelectBinaryExpr(expr.Left)
		if err != nil {
			return nil, err
		}
		right, err := e.parseSelectBinaryExpr(expr.Right)
		if err != nil {
			return nil, err
		}
		return GetBinaryFunc(expr.Operator, []Function{left, right})
	case *sqlparser.FuncExpr:
		name, args, err := e.parseFunction(expr)
		if err != nil {
			return nil, err
		}
		function, levelFlag, err := GetAggFunc(name, args, "", e.DB, e.Table)
		if err != nil {
			return nil, err
		}
		// 通过metric判断view是否拆层
		e.SetLevelFlag(levelFlag)
		return function.(Function), nil
	case *sqlparser.ParenExpr:
		// 括号
		return e.parseSelectBinaryExpr(expr.Expr)
	case *sqlparser.SQLVal:
		return &Field{Value: sqlparser.String(expr)}, nil
	default:
		// TODO: 报错
		return nil, nil
	}
}

func (e *CHEngine) AddGroup(group string) error {
	stmt, err := GetGroup(group, e.asTagMap)
	if err != nil {
		return err
	}
	if stmt != nil {
		e.Statements = append(e.Statements, stmt)
	}
	return nil
}

func (e *CHEngine) AddTable(table string) {
	stmt := &Table{Value: table}
	e.Statements = append(e.Statements, stmt)
}

func (e *CHEngine) AddTag(tag string, alias string) error {
	stmt, err := GetTagTranslator(tag, alias)
	if err != nil {
		return err
	}
	e.Statements = append(e.Statements, stmt)
	return nil
}

func (e *CHEngine) AddFunction(name string, args []string, alias string) error {
	function, levelFlag, err := GetAggFunc(name, args, alias, e.DB, e.Table)
	if err != nil {
		return err
	}
	// 通过metric判断view是否拆层
	e.SetLevelFlag(levelFlag)
	e.Statements = append(e.Statements, function)
	return nil
}

func (e *CHEngine) AddTagFunction(name string, args []string, alias string) error {
	function, err := GetTagFunctionTranslator(name, args, alias)
	if err != nil {
		return err
	}
	e.Statements = append(e.Statements, function)
	return nil
}

func (e *CHEngine) SetLevelFlag(flag int) {
	if flag > e.Model.MetricsLevelFlag {
		e.Model.MetricsLevelFlag = flag
	}
}

func (e *CHEngine) parseWhere(node sqlparser.Expr, w *Where) (view.Node, error) {
	switch node := node.(type) {
	case *sqlparser.AndExpr:
		left, err := e.parseWhere(node.Left, w)
		if err != nil {
			return left, err
		}
		right, err := e.parseWhere(node.Right, w)
		if err != nil {
			return right, err
		}
		op := view.Operator{Type: view.AND}
		return &view.BinaryExpr{Left: left, Right: right, Op: &op}, nil
	case *sqlparser.OrExpr:
		left, err := e.parseWhere(node.Left, w)
		if err != nil {
			return left, err
		}
		right, err := e.parseWhere(node.Right, w)
		if err != nil {
			return right, err
		}
		op := view.Operator{Type: view.OR}
		return &view.BinaryExpr{Left: left, Right: right, Op: &op}, nil
	case *sqlparser.NotExpr:
		expr, err := e.parseWhere(node.Expr, w)
		if err != nil {
			return expr, err
		}
		op := view.Operator{Type: view.NOT}
		return &view.UnaryExpr{Op: &op, Expr: expr}, nil
	case *sqlparser.ParenExpr: // 括号
		expr, err := e.parseWhere(node.Expr, w)
		if err != nil {
			return expr, err
		}
		return &view.Nested{Expr: expr}, nil
	case *sqlparser.ComparisonExpr:
		switch expr := node.Left.(type) {
		case *sqlparser.ColName:
			whereTag := sqlparser.String(node.Left)
			whereValue := sqlparser.String(node.Right)
			stmt := GetWhere(whereTag, whereValue)
			return stmt.Trans(node, w, e.asTagMap)
		case *sqlparser.FuncExpr, *sqlparser.BinaryExpr:
			function, err := e.parseSelectBinaryExpr(expr)
			if err != nil {
				return nil, err
			}
			outfunc := function.Trans(e.Model)
			stmt := &WhereFunction{Function: outfunc, Value: sqlparser.String(node.Right)}
			return stmt.Trans(node, w, e.asTagMap)
		}

	}
	return nil, nil
}

// 翻译单元,翻译结果写入view.Model
type Statement interface {
	Format(*view.Model)
}

func LoadDbDescriptions(dbDescriptions map[string]interface{}) {
	dbData, ok := dbDescriptions["clickhouse"]
	if !ok {
		return
	}

	dbDataMap := dbData.(map[string]interface{})
	// 加载metric定义
	if metricData, ok := dbDataMap["metrics"]; ok {
		for db, tables := range DB_TABLE_MAP {
			for _, table := range tables {
				loadMetrics := metrics.LoadMetrics(db, table, metricData.(map[string]interface{}))
				metrics.MergeMetrics(db, table, loadMetrics)
			}
		}
	}
	// 加载tag定义及部分tag的enum取值
	if tagData, ok := dbDataMap["tag"]; ok {
		tagdescription.LoadTagDescriptions(tagData.(map[string]interface{}))
	}

}
