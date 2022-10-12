/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package clickhouse

import (
	"errors"
	"fmt"
	//"github.com/k0kubun/pp"
	"regexp"
	"strings"

	logging "github.com/op/go-logging"
	"github.com/xwb1989/sqlparser"

	"github.com/deepflowys/deepflow/server/querier/common"
	"github.com/deepflowys/deepflow/server/querier/config"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse/client"
	chCommon "github.com/deepflowys/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse/metrics"
	tagdescription "github.com/deepflowys/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse/view"
	"github.com/deepflowys/deepflow/server/querier/parse"
)

var log = logging.MustGetLogger("clickhouse")

type CHEngine struct {
	Model         *view.Model
	Statements    []Statement
	DB            string
	Table         string
	DataSource    string
	asTagMap      map[string]string
	ColumnSchemas []*client.ColumnSchema
	View          *view.View
}

func (e *CHEngine) ExecuteQuery(sql string, query_uuid string) (map[string][]interface{}, map[string]interface{}, error) {
	// 解析show开头的sql
	// show metrics/tags from <table_name> 例：show metrics/tags from l4_flow_log
	log.Debugf("query_uuid: %s | raw sql: %s", query_uuid, sql)
	result, isShow, err := e.ParseShowSql(sql)
	if isShow {
		if err != nil {
			return nil, nil, err
		}
		return result, nil, nil
	}
	sqlList := strings.SplitAfterN(sql, "WHERE", 2)
	if len(sqlList) == 1 {
		sqlList = strings.SplitAfterN(sql, "where", 2)
	}
	if len(sqlList) > 1 {
		var rgx = regexp.MustCompile(`(Enum\(.*?\))`)
		rs := rgx.FindAllStringSubmatch(sqlList[1], -1)
		rMap := map[string]string{}
		for _, r := range rs {
			rMap[r[1]] = r[1]
		}
		for _, value := range rMap {
			sqlList[1] = strings.ReplaceAll(sqlList[1], value, "`"+value+"`")
		}
		sql = sqlList[0] + sqlList[1]
	}
	debug := &client.Debug{
		IP:        config.Cfg.Clickhouse.Host,
		QueryUUID: query_uuid,
	}
	parser := parse.Parser{Engine: e}
	err = parser.ParseSQL(sql)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	for _, stmt := range e.Statements {
		stmt.Format(e.Model)
	}
	FormatInnerTime(e.Model)
	// 使用Model生成View
	e.View = view.NewView(e.Model)
	chSql := e.ToSQLString()
	callbacks := e.View.GetCallbacks()
	debug.Sql = chSql
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       e.DB,
		Debug:    debug,
	}
	ColumnSchemaMap := make(map[string]*client.ColumnSchema)
	for _, ColumnSchema := range e.ColumnSchemas {
		ColumnSchemaMap[ColumnSchema.Name] = ColumnSchema
	}
	params := &client.QueryParams{
		Sql:             chSql,
		Callbacks:       callbacks,
		QueryUUID:       query_uuid,
		ColumnSchemaMap: ColumnSchemaMap,
	}
	rst, err := chClient.DoQuery(params)
	if err != nil {
		return nil, debug.Get(), err
	}
	return rst, debug.Get(), err
}

func (e *CHEngine) Init() {
	e.Model = view.NewModel()
	e.Model.DB = e.DB
}

func (e *CHEngine) ParseShowSql(sql string) (map[string][]interface{}, bool, error) {
	sqlSplit := strings.Split(sql, " ")
	if strings.ToLower(sqlSplit[0]) != "show" {
		return nil, false, nil
	}
	var table string
	var where string
	for i, item := range sqlSplit {
		if strings.ToLower(item) == "from" {
			table = sqlSplit[i+1]
			break
		}
		if strings.ToLower(item) == "where" {
			where = strings.Join(sqlSplit[i+1:], " ")
		}
	}
	switch strings.ToLower(sqlSplit[1]) {
	case "metrics":
		if len(sqlSplit) > 2 && strings.ToLower(sqlSplit[2]) == "functions" {
			funcs, err := metrics.GetFunctionDescriptions()
			return funcs, true, err
		} else {
			metrics, err := metrics.GetMetricsDescriptions(e.DB, table, where)
			return metrics, true, err
		}
	case "tag":
		// show tag {tag} values from table
		if len(sqlSplit) < 6 {
			return nil, true, errors.New(fmt.Sprintf("parse show sql error, sql: '%s' not support", sql))
		}
		if strings.ToLower(sqlSplit[3]) == "values" {
			values, err := tagdescription.GetTagValues(e.DB, table, sql)
			return values, true, err
		}
		return nil, true, errors.New(fmt.Sprintf("parse show sql error, sql: '%s' not support", sql))
	case "tags":
		data, err := tagdescription.GetTagDescriptions(e.DB, table, sql)
		return data, true, err
	case "tables":
		return GetTables(e.DB), true, nil
	case "databases":
		return GetDatabases(), true, nil
	}
	return nil, true, errors.New(fmt.Sprintf("parse show sql error, sql: '%s' not support", sql))
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
			as := chCommon.ParseAlias(item.As)
			colName, ok := item.Expr.(*sqlparser.ColName)
			if ok {
				e.asTagMap[as] = chCommon.ParseAlias(colName)
			}
			function, ok := item.Expr.(*sqlparser.FuncExpr)
			if ok {
				e.asTagMap[as] = strings.Trim(sqlparser.String(function.Name), "`")
			}
			binary, ok := item.Expr.(*sqlparser.BinaryExpr)
			if ok {
				e.asTagMap[as] = sqlparser.String(binary)
			}
		}
	}
	return nil
}

func (e *CHEngine) TransWhere(node *sqlparser.Where) error {
	// 生成where的statement
	whereStmt := Where{time: e.Model.Time}
	// 解析ast树并生成view.Node结构
	expr, err := e.parseWhere(node.Expr, &whereStmt, false)
	filter := view.Filters{Expr: expr}
	whereStmt.filter = &filter
	e.Statements = append(e.Statements, &whereStmt)
	return err
}

func (e *CHEngine) TransHaving(node *sqlparser.Where) error {
	// 生成having的statement
	havingStmt := Having{Where{}}
	// 解析ast树并生成view.Node结构
	// having中的metric需要在trans之前确定是否分层，所以需要提前遍历
	_, err := e.parseWhere(node.Expr, &havingStmt.Where, true)
	if err != nil {
		return err
	}
	expr, err := e.parseWhere(node.Expr, &havingStmt.Where, false)
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
			table := strings.Trim(sqlparser.String(from), "`")
			e.Table = table
			// ext_metrics只有metrics表，使用virtual_table_name做过滤区分
			if e.DB == "ext_metrics" {
				table = "metrics"
			}
			if e.DataSource != "" {
				e.AddTable(fmt.Sprintf("%s.`%s.%s`", e.DB, table, e.DataSource))
			} else {
				e.AddTable(fmt.Sprintf("%s.`%s`", e.DB, table))
			}
			interval, err := chCommon.GetDatasourceInterval(e.DB, e.Table, e.DataSource)
			if err != nil {
				log.Error(err)
			}
			e.Model.Time.DatasourceInterval = interval
			virtualTableFilter, ok := GetVirtualTableFilter(e.DB, e.Table)
			if ok {
				whereStmt := Where{}
				filter := view.Filters{Expr: virtualTableFilter}
				whereStmt.filter = &filter
				e.Statements = append(e.Statements, &whereStmt)
			}
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
	if e.View == nil {
		for _, stmt := range e.Statements {
			stmt.Format(e.Model)
		}
		FormatInnerTime(e.Model)
		// 使用Model生成View
		e.View = view.NewView(e.Model)
	}
	// View生成clickhouse-sql
	chSql := e.View.ToString()
	return chSql
}

func (e *CHEngine) parseOrderBy(order *sqlparser.Order) error {
	switch expr := order.Expr.(type) {
	case *sqlparser.FuncExpr:
		e.Model.Orders.Append(
			&view.Order{
				SortBy:  sqlparser.String(expr),
				OrderBy: order.Direction,
				IsField: false,
			},
		)
	case *sqlparser.ColName:
		e.Model.Orders.Append(
			&view.Order{
				SortBy:  chCommon.ParseAlias(expr),
				OrderBy: order.Direction,
				IsField: true,
			},
		)
	}
	return nil
}

// 解析GroupBy
func (e *CHEngine) parseGroupBy(group sqlparser.Expr) error {
	//var args []string
	switch expr := group.(type) {
	// 普通字符串
	case *sqlparser.ColName, *sqlparser.SQLVal:
		groupTag := chCommon.ParseAlias(expr)
		err := e.AddGroup(groupTag)
		if err != nil {
			return err
		}
		_, ok := e.asTagMap[groupTag]
		if !ok {
			err := e.AddTag(groupTag, "")
			if err != nil {
				return err
			}
		}
		// TODO: 特殊处理塞进group的fromat中
		whereStmt := Where{}
		notNullExpr, ok := GetNotNullFilter(groupTag, e.asTagMap, e.DB, e.Table)
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
	as := chCommon.ParseAlias(item.As)
	if as != "" {
		e.ColumnSchemas = append(e.ColumnSchemas, client.NewColumnSchema(as))
	} else {
		e.ColumnSchemas = append(e.ColumnSchemas, client.NewColumnSchema(chCommon.ParseAlias(item.Expr)))
	}
	//var args []string
	switch expr := item.Expr.(type) {
	// 普通字符串
	case *sqlparser.ParenExpr:
		binFunction, err := e.parseSelectBinaryExpr(expr)
		if err != nil {
			return err
		}
		binFunction.SetAlias(as)
		e.Statements = append(e.Statements, binFunction)
		return nil
	case *sqlparser.ColName, *sqlparser.SQLVal:
		err := e.AddTag(chCommon.ParseAlias(expr), as)
		if err != nil {
			return err
		}
		return nil
	// func(field/tag)
	case *sqlparser.FuncExpr:
		// 二级运算符
		if common.IsValueInSliceString(sqlparser.String(expr.Name), view.MATH_FUNCTIONS) {
			binFunction, err := e.parseSelectBinaryExpr(expr)
			if err != nil {
				return err
			}
			binFunction.SetAlias(as)
			e.Statements = append(e.Statements, binFunction)
			return nil
		}
		name, args, err := e.parseFunction(expr)
		if err != nil {
			return err
		}
		name = strings.Trim(name, "`")
		function, levelFlag, unit, err := GetAggFunc(name, args, as, e.DB, e.Table)
		if err != nil {
			return err
		}
		if function != nil {
			// 通过metric判断view是否拆层
			e.SetLevelFlag(levelFlag)
			e.Statements = append(e.Statements, function)
			e.ColumnSchemas[len(e.ColumnSchemas)-1].Type = client.COLUMN_SCHEMA_TYPE_METRICS
			if unit != "" {
				e.ColumnSchemas[len(e.ColumnSchemas)-1].Unit = unit
			}
			return nil
		}
		tagFunction, err := GetTagFunction(name, args, as, e.DB, e.Table)
		if err != nil {
			return err
		}
		if tagFunction != nil {
			// time需要被最先解析
			if name == "time" {
				tagFunction.(*Time).Trans(e.Model)
				e.Statements = append([]Statement{tagFunction}, e.Statements...)
			} else {
				e.Statements = append(e.Statements, tagFunction)
			}
			return nil
		}
		return errors.New(fmt.Sprintf("function: %s not support", sqlparser.String(expr)))
	// field +=*/ field 运算符
	case *sqlparser.BinaryExpr:
		binFunction, err := e.parseSelectBinaryExpr(expr)
		if err != nil {
			return err
		}
		binFunction.SetAlias(as)
		e.Statements = append(e.Statements, binFunction)
		return nil
	default:
		return errors.New(fmt.Sprintf("select: %s(%T) not support", sqlparser.String(expr), expr))
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
			return nil, errors.New(fmt.Sprintf("Operator: %s not support in binary", expr.Operator))
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
		// 嵌套算子
		if common.IsValueInSliceString(sqlparser.String(expr.Name), view.MATH_FUNCTIONS) {
			args := []Function{}
			for _, argExpr := range expr.Exprs {
				arg, err := e.parseSelectBinaryExpr(argExpr.(*sqlparser.AliasedExpr).Expr)
				if err != nil {
					return nil, err
				}
				args = append(args, arg)
			}
			if function, ok := metrics.METRICS_FUNCTIONS_MAP[sqlparser.String(expr.Name)]; ok {
				e.ColumnSchemas[len(e.ColumnSchemas)-1].Unit = strings.ReplaceAll(function.UnitOverwrite, "$unit", e.ColumnSchemas[len(e.ColumnSchemas)-1].Unit)
			}
			return GetBinaryFunc(sqlparser.String(expr.Name), args)
		}
		name, args, err := e.parseFunction(expr)
		if err != nil {
			return nil, err
		}
		aggfunction, levelFlag, unit, err := GetAggFunc(name, args, "", e.DB, e.Table)
		if err != nil {
			return nil, err
		}
		if aggfunction != nil {
			// 通过metric判断view是否拆层
			e.SetLevelFlag(levelFlag)
			e.ColumnSchemas[len(e.ColumnSchemas)-1].Type = client.COLUMN_SCHEMA_TYPE_METRICS
			if unit != "" && e.ColumnSchemas[len(e.ColumnSchemas)-1].Unit == "" {
				e.ColumnSchemas[len(e.ColumnSchemas)-1].Unit = unit
			}
			return aggfunction.(Function), nil
		}
		tagFunction, err := GetTagFunction(name, args, "", e.DB, e.Table)
		if err != nil {
			return nil, err
		}
		if tagFunction != nil {
			function, ok := tagFunction.(Function)
			if !ok {
				return nil, errors.New(fmt.Sprintf("tagfunction: %s not support in binary", sqlparser.String(expr)))
			}
			return function, nil
		}
		return nil, errors.New(fmt.Sprintf("function: %s not support in binary", sqlparser.String(expr)))
	case *sqlparser.ParenExpr:
		// 括号
		return e.parseSelectBinaryExpr(expr.Expr)
	case *sqlparser.SQLVal:
		return &Field{Value: sqlparser.String(expr)}, nil
	case *sqlparser.ColName:
		field := sqlparser.String(expr)
		fieldFunc, err := GetFieldFunc(field)
		if err != nil {
			return nil, err
		}
		if fieldFunc != nil {
			return fieldFunc, nil
		}
		metricStruct, ok := metrics.GetMetrics(field, e.DB, e.Table)
		if ok {
			return &Field{Value: metricStruct.DBField}, nil
		}
		return &Field{Value: sqlparser.String(expr)}, nil
	default:
		// TODO: 报错
		return nil, nil
	}
}

func (e *CHEngine) AddGroup(group string) error {
	stmt, err := GetGroup(group, e.asTagMap, e.DB, e.Table)
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
	stmt, err := GetTagTranslator(tag, alias, e.DB, e.Table)
	if err != nil {
		return err
	}
	if stmt != nil {
		e.Statements = append(e.Statements, stmt)
		return nil
	}
	stmt, err = GetMetricsTag(tag, alias, e.DB, e.Table)
	if err != nil {
		return err
	}
	if stmt != nil {
		e.Statements = append(e.Statements, stmt)
		return nil
	}
	stmt = GetDefaultTag(tag, alias)
	e.Statements = append(e.Statements, stmt)
	return nil
}

func (e *CHEngine) SetLevelFlag(flag int) {
	if flag > e.Model.MetricsLevelFlag {
		e.Model.MetricsLevelFlag = flag
	}
	e.Model.HasAggFunc = true
}

func (e *CHEngine) parseWhere(node sqlparser.Expr, w *Where, isCheck bool) (view.Node, error) {
	switch node := node.(type) {
	case *sqlparser.AndExpr:
		left, err := e.parseWhere(node.Left, w, isCheck)
		if err != nil {
			return left, err
		}
		right, err := e.parseWhere(node.Right, w, isCheck)
		if err != nil {
			return right, err
		}
		op := view.Operator{Type: view.AND}
		return &view.BinaryExpr{Left: left, Right: right, Op: &op}, nil
	case *sqlparser.OrExpr:
		left, err := e.parseWhere(node.Left, w, isCheck)
		if err != nil {
			return left, err
		}
		right, err := e.parseWhere(node.Right, w, isCheck)
		if err != nil {
			return right, err
		}
		op := view.Operator{Type: view.OR}
		return &view.BinaryExpr{Left: left, Right: right, Op: &op}, nil
	case *sqlparser.NotExpr:
		expr, err := e.parseWhere(node.Expr, w, isCheck)
		if err != nil {
			return expr, err
		}
		op := view.Operator{Type: view.NOT}
		return &view.UnaryExpr{Op: &op, Expr: expr}, nil
	case *sqlparser.ParenExpr: // 括号
		expr, err := e.parseWhere(node.Expr, w, isCheck)
		if err != nil {
			return expr, err
		}
		return &view.Nested{Expr: expr}, nil
	case *sqlparser.ComparisonExpr:
		var comparExpr sqlparser.Expr
		switch expr := node.Left.(type) {
		case *sqlparser.ParenExpr: // 括号
			comparExpr = expr.Expr
		default:
			comparExpr = expr
		}
		switch comparExpr.(type) {
		case *sqlparser.ColName, *sqlparser.SQLVal:
			whereTag := chCommon.ParseAlias(node.Left)
			if (e.DB == "ext_metrics" || e.DB == "deepflow_system") && strings.Contains(whereTag, "metrics.") {
				metricStruct, ok := metrics.GetMetrics(whereTag, e.DB, e.Table)
				if ok {
					whereTag = metricStruct.DBField
				}
			}
			whereValue := sqlparser.String(node.Right)
			stmt := GetWhere(whereTag, whereValue)
			return stmt.Trans(node, w, e.asTagMap, e.DB, e.Table)
		case *sqlparser.FuncExpr, *sqlparser.BinaryExpr:
			function, err := e.parseSelectBinaryExpr(comparExpr)
			if err != nil {
				return nil, err
			}
			if isCheck {
				return nil, nil
			}
			outfunc := function.Trans(e.Model)
			stmt := &WhereFunction{Function: outfunc, Value: sqlparser.String(node.Right)}
			return stmt.Trans(node, w, e.asTagMap, e.DB, e.Table)
		}

	}
	return nil, errors.New(fmt.Sprintf("parse where error: %s(%T)", sqlparser.String(node), node))
}

// 翻译单元,翻译结果写入view.Model
type Statement interface {
	Format(*view.Model)
}

func LoadDbDescriptions(dbDescriptions map[string]interface{}) error {
	dbData, ok := dbDescriptions["clickhouse"]
	if !ok {
		return errors.New("clickhouse not in dbDescription")
	}

	dbDataMap := dbData.(map[string]interface{})
	// 加载metric定义
	if metricData, ok := dbDataMap["metrics"]; ok {
		for db, tables := range chCommon.DB_TABLE_MAP {
			if db == "ext_metrics" || db == "deepflow_system" {
				continue
			}
			for _, table := range tables {
				loadMetrics, err := metrics.LoadMetrics(db, table, metricData.(map[string]interface{}))
				if err != nil {
					return err
				}
				err = metrics.MergeMetrics(db, table, loadMetrics)
				if err != nil {
					return err
				}
			}
		}
	} else {
		return errors.New("clickhouse not has metrics")
	}
	// 加载tag定义及部分tag的enum取值
	if tagData, ok := dbDataMap["tag"]; ok {
		err := tagdescription.LoadTagDescriptions(tagData.(map[string]interface{}))
		if err != nil {
			return err
		}
	} else {
		return errors.New("clickhouse not has tag")
	}
	return nil
}
