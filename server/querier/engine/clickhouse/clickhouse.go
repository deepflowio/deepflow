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
	"context"
	"errors"
	"fmt"
	//"github.com/k0kubun/pp"
	"strings"

	logging "github.com/op/go-logging"
	"github.com/xwb1989/sqlparser"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
	tagdescription "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
	"github.com/deepflowio/deepflow/server/querier/parse"
)

var log = logging.MustGetLogger("clickhouse")

var DEFAULT_LIMIT = "10000"

type CHEngine struct {
	Model         *view.Model
	Statements    []Statement
	DB            string
	Table         string
	DataSource    string
	asTagMap      map[string]string
	ColumnSchemas []*common.ColumnSchema
	View          *view.View
	Context       context.Context
}

func (e *CHEngine) ExecuteQuery(args *common.QuerierParams) (*common.Result, map[string]interface{}, error) {
	// 解析show开头的sql
	// show metrics/tags from <table_name> 例：show metrics/tags from l4_flow_log
	var sqlList []string
	var err error
	sql := args.Sql
	query_uuid := args.QueryUUID
	log.Debugf("query_uuid: %s | raw sql: %s", query_uuid, sql)
	// Parse slimitSql
	slimitResult, slimitDebug, err := e.ParseSlimitSql(sql, args)
	if err != nil {
		return nil, nil, err
	}
	if slimitResult != nil {
		return slimitResult, slimitDebug, err
	}
	// Parse showSql
	result, sqlList, isShow, err := e.ParseShowSql(sql)
	if isShow {
		if err != nil {
			return nil, nil, err
		}
		if len(sqlList) == 0 {
			return result, nil, nil
		}
	}
	debug := &client.Debug{
		IP:        config.Cfg.Clickhouse.Host,
		QueryUUID: query_uuid,
	}
	parser := parse.Parser{Engine: e}
	if len(sqlList) > 0 {
		e.DB = "flow_tag"
		results := &common.Result{}
		chClient := client.Client{
			Host:     config.Cfg.Clickhouse.Host,
			Port:     config.Cfg.Clickhouse.Port,
			UserName: config.Cfg.Clickhouse.User,
			Password: config.Cfg.Clickhouse.Password,
			DB:       e.DB,
			Debug:    debug,
			Context:  e.Context,
		}
		ColumnSchemaMap := make(map[string]*common.ColumnSchema)
		for _, ColumnSchema := range e.ColumnSchemas {
			ColumnSchemaMap[ColumnSchema.Name] = ColumnSchema
		}
		for _, showSql := range sqlList {
			err := parser.ParseSQL(showSql)
			if err != nil {
				log.Error(err)
				return nil, nil, err
			}
			for _, stmt := range e.Statements {
				stmt.Format(e.Model)
			}
			FormatLimit(e.Model)
			// 使用Model生成View
			e.View = view.NewView(e.Model)
			chSql := e.ToSQLString()
			callbacks := e.View.GetCallbacks()
			debug.Sql = chSql
			params := &client.QueryParams{
				Sql:             chSql,
				Callbacks:       callbacks,
				QueryUUID:       query_uuid,
				ColumnSchemaMap: ColumnSchemaMap,
			}
			result, err := chClient.DoQuery(params)
			if err != nil {
				log.Error(err)
				return nil, nil, err
			}
			if result != nil {
				results.Values = append(results.Values, result.Values...)
				results.Columns = result.Columns
			}
		}
		return results, debug.Get(), nil
	}
	err = parser.ParseSQL(sql)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	for _, stmt := range e.Statements {
		stmt.Format(e.Model)
	}
	FormatModel(e.Model)
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
		Context:  e.Context,
	}
	ColumnSchemaMap := make(map[string]*common.ColumnSchema)
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

func (e *CHEngine) ParseShowSql(sql string) (*common.Result, []string, bool, error) {
	sqlSplit := strings.Split(sql, " ")
	if strings.ToLower(sqlSplit[0]) != "show" {
		return nil, []string{}, false, nil
	}
	if strings.ToLower(sqlSplit[1]) == "language" {
		result := &common.Result{}
		result.Columns = []interface{}{"language"}
		result.Values = []interface{}{[]string{config.Cfg.Language}}
		return result, []string{}, true, nil
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
			return funcs, []string{}, true, err
		} else {
			metrics, err := metrics.GetMetricsDescriptions(e.DB, table, where, e.Context)
			return metrics, []string{}, true, err
		}
	case "tag":
		// show tag {tag} values from table
		if len(sqlSplit) < 6 {
			return nil, []string{}, true, errors.New(fmt.Sprintf("parse show sql error, sql: '%s' not support", sql))
		}
		if strings.ToLower(sqlSplit[3]) == "values" {
			result, sqlList, err := tagdescription.GetTagValues(e.DB, table, sql)
			return result, sqlList, true, err
		}
		return nil, []string{}, true, errors.New(fmt.Sprintf("parse show sql error, sql: '%s' not support", sql))
	case "tags":
		data, err := tagdescription.GetTagDescriptions(e.DB, table, sql, e.Context)
		return data, []string{}, true, err
	case "tables":
		return GetTables(e.DB, e.Context), []string{}, true, nil
	case "databases":
		return GetDatabases(), []string{}, true, nil
	}
	return nil, []string{}, true, errors.New(fmt.Sprintf("parse show sql error, sql: '%s' not support", sql))
}

func (e *CHEngine) ParseSlimitSql(sql string, args *common.QuerierParams) (*common.Result, map[string]interface{}, error) {
	if !strings.Contains(sql, "SLIMIT") && !strings.Contains(sql, "slimit") {
		return nil, nil, nil
	}
	newSql := strings.ReplaceAll(sql, " SLIMIT ", " slimit ")
	newSql = strings.ReplaceAll(newSql, " LIMIT ", " limit ")
	newSql = strings.ReplaceAll(newSql, " WHERE ", " where ")
	newSql = strings.ReplaceAll(newSql, " GROUP BY ", " group by ")
	newSqlSlice := []string{}
	if !strings.Contains(newSql, " where ") {
		if strings.Contains(newSql, " group by ") {
			groupSlice := strings.Split(newSql, " group by ")
			newSqlSlice = append(newSqlSlice, groupSlice[0])
			newSqlSlice = append(newSqlSlice, " where 1=1 group by ")
			newSqlSlimitSlice := strings.Split(groupSlice[1], " slimit ")
			newSqlSlice = append(newSqlSlice, groupSlice[0])
			if strings.Contains(newSqlSlimitSlice[1], " limit ") {
				newSqlLimitSlice := strings.Split(newSqlSlimitSlice[1], " limit ")
				newSqlSlice = append(newSqlSlice, fmt.Sprintf(" limit %s", newSqlLimitSlice[1]))
			}
			newSql = strings.Join(newSqlSlice, "")
		}
	} else {
		newSqlSlimitSlice := strings.Split(newSql, " slimit ")
		newSqlSlice = append(newSqlSlice, newSqlSlimitSlice[0])
		if strings.Contains(newSqlSlimitSlice[1], " limit ") {
			newSqlLimitSlice := strings.Split(newSqlSlimitSlice[1], " limit ")
			newSqlSlice = append(newSqlSlice, fmt.Sprintf(" limit %s", newSqlLimitSlice[1]))
		}
		newSql = strings.Join(newSqlSlice, "")
	}
	stmt, err := sqlparser.Parse(newSql)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	innerSelectSlice := []string{}
	outerWhereLeftSlice := []string{}
	outerWhereLeftAppendSlice := []string{}

	innerGroupBySlice := []string{}
	innerSql := ""
	pStmt := stmt.(*sqlparser.Select)
	table := ""
	// From解析
	if pStmt.From != nil {
		for _, from := range pStmt.From {
			switch from := from.(type) {
			case *sqlparser.AliasedTableExpr:
				// 解析Table类型
				table = sqlparser.String(from)
			}
		}
	}

	showTagsSql := "show tags from " + table
	tags, _, _, err := e.ParseShowSql(showTagsSql)
	tagsSlice := []string{}
	for _, col := range tags.Values {
		colSlice := col.([]interface{})
		tagsSlice = append(tagsSlice, colSlice[0].(string))
		tagsSlice = append(tagsSlice, colSlice[1].(string))
		tagsSlice = append(tagsSlice, colSlice[2].(string))
	}
	// Select解析
	if pStmt.SelectExprs != nil {
		for _, tag := range pStmt.SelectExprs {
			item, ok := tag.(*sqlparser.AliasedExpr)
			if ok {
				as := sqlparser.String(item.As)
				colName, ok := item.Expr.(*sqlparser.ColName)
				if ok && (common.IsValueInSliceString(strings.Trim(strings.Trim(sqlparser.String(colName), "'"), "`"), tagsSlice) || strings.Contains(sqlparser.String(colName), "_id")) {
					if as != "" {
						selectTag := sqlparser.String(colName) + " AS " + as
						innerSelectSlice = append(innerSelectSlice, selectTag)
						outerWhereLeftSlice = append(outerWhereLeftSlice, as)
					} else {
						innerSelectSlice = append(innerSelectSlice, sqlparser.String(colName))
						outerWhereLeftSlice = append(outerWhereLeftSlice, sqlparser.String(colName))
					}
					for _, suffix := range []string{"", "_0", "_1"} {
						for _, resourceName := range []string{"resource_gl0", "auto_instance", "resource_gl1", "resource_gl2", "auto_service"} {
							resourceTypeSuffix := "auto_service_type" + suffix
							if common.IsValueInSliceString(resourceName, []string{"resource_gl0", "auto_instance"}) {
								resourceTypeSuffix = "auto_instance_type" + suffix
							}
							if sqlparser.String(colName) == resourceName+suffix {
								outerWhereLeftAppendSlice = append(outerWhereLeftAppendSlice, resourceTypeSuffix)
							}
						}
					}
				}
				funcName, ok := item.Expr.(*sqlparser.FuncExpr)
				if ok && strings.HasPrefix(sqlparser.String(funcName), "enum") {
					innerSelectSlice = append(innerSelectSlice, strings.ReplaceAll(sqlparser.String(funcName), "enum", "Enum"))
					outerWhereLeftSlice = append(outerWhereLeftSlice, "`"+strings.ReplaceAll(sqlparser.String(funcName), "enum", "Enum")+"`")
				}
			}
		}
	}
	// GroupBy解析
	if pStmt.GroupBy != nil {
		for _, group := range pStmt.GroupBy {
			colName, ok := group.(*sqlparser.ColName)
			if ok {
				if sqlparser.String(colName) == "toi" || strings.Contains(sqlparser.String(colName), "time") {
					continue
				} else if strings.Contains(sqlparser.String(colName), "node_type") || strings.Contains(sqlparser.String(colName), "icon_id") {
					continue
					// Inner sql remove star grouping
				} else if common.IsValueInSliceString(sqlparser.String(colName), []string{"_", "_0", "_1"}) {
					continue
				}
				groupTag := sqlparser.String(colName)
				innerGroupBySlice = append(innerGroupBySlice, groupTag)
			}
			funcName, ok := group.(*sqlparser.FuncExpr)
			if ok {
				if strings.HasPrefix(sqlparser.String(funcName), "time") {
					continue
				}
				groupTag := sqlparser.String(funcName)
				innerGroupBySlice = append(innerGroupBySlice, groupTag)
			}
		}
	}
	innerTransSql := ""
	// No internal sql required when only star grouping
	if len(innerSelectSlice) > 0 {
		innerSelectSql := strings.Join(innerSelectSlice, ",")
		innerGroupBySql := strings.Join(innerGroupBySlice, ",")
		lowerSql := strings.ReplaceAll(sql, " WHERE ", " where ")
		lowerSql = strings.ReplaceAll(lowerSql, " GROUP BY ", " group by ")
		lowerSql = strings.ReplaceAll(lowerSql, " SLIMIT ", " slimit ")
		lowerSql = strings.ReplaceAll(lowerSql, " LIMIT ", " limit ")
		lowerSql = strings.ReplaceAll(lowerSql, " FROM ", " from ")
		if strings.Contains(lowerSql, " limit ") {
			lowerSqlLimitSlice := strings.Split(lowerSql, " limit ")
			lowerSql = lowerSqlLimitSlice[0]
		}
		if strings.Contains(lowerSql, " where ") {
			sqlSlice := strings.Split(lowerSql, " where ")
			if strings.Contains(lowerSql, " group by ") {
				whereSlice := strings.Split(sqlSlice[1], " group by ")
				whereSql := whereSlice[0]
				limitSlice := strings.Split(whereSlice[1], " slimit ")
				limitSql := limitSlice[1]
				innerSql = "SELECT " + innerSelectSql + " FROM " + table + " WHERE " + whereSql + " GROUP BY " + innerGroupBySql + " LIMIT " + limitSql
			}
		} else {
			if strings.Contains(lowerSql, " group by ") {
				groupSlice := strings.Split(lowerSql, " group by ")
				limitSlice := strings.Split(groupSlice[1], " slimit ")
				limitSql := limitSlice[1]
				innerSql = "SELECT " + innerSelectSql + " FROM " + table + " GROUP BY " + innerGroupBySql + " LIMIT " + limitSql
			}
		}
		innerEngine := &CHEngine{DB: e.DB, DataSource: e.DataSource, Context: e.Context}
		innerEngine.Init()
		innerParser := parse.Parser{Engine: innerEngine}
		err = innerParser.ParseSQL(innerSql)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}
		for _, stmt := range innerEngine.Statements {
			stmt.Format(innerEngine.Model)
		}
		FormatModel(innerEngine.Model)
		// 使用Model生成View
		innerEngine.View = view.NewView(innerEngine.Model)
		innerTransSql = innerEngine.ToSQLString()
	}

	outerEngine := &CHEngine{DB: e.DB, DataSource: e.DataSource, Context: e.Context}
	outerEngine.Init()
	outerParser := parse.Parser{Engine: outerEngine}
	err = outerParser.ParseSQL(newSql)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	for _, stmt := range outerEngine.Statements {
		stmt.Format(outerEngine.Model)
	}
	FormatModel(outerEngine.Model)
	// 使用Model生成View
	outerEngine.View = view.NewView(outerEngine.Model)
	outerTransSql := outerEngine.ToSQLString()
	outerSlice := []string{}
	outerWhereLeftSlice = append(outerWhereLeftSlice, outerWhereLeftAppendSlice...)
	outerWhereLeftSql := strings.Join(outerWhereLeftSlice, ",")
	outerSql := ""
	// No internal sql required when only star grouping
	if len(innerSelectSlice) > 0 {
		if strings.Contains(outerTransSql, " PREWHERE ") {
			oldWhereSlice := strings.Split(outerTransSql, " PREWHERE ")
			outerSlice = append(outerSlice, oldWhereSlice[0])
			outerSlice = append(outerSlice, " PREWHERE ("+outerWhereLeftSql+") IN ("+innerTransSql+") AND ")
			outerSlice = append(outerSlice, oldWhereSlice[1])
			outerSql = strings.Join(outerSlice, "")
		}
	} else {
		outerSql = outerTransSql
	}
	query_uuid := args.QueryUUID
	debug := &client.Debug{
		IP:        config.Cfg.Clickhouse.Host,
		QueryUUID: query_uuid,
	}
	outerSql = strings.Replace(outerSql, ") IN (", ") GLOBAL IN (", 1)
	callbacks := outerEngine.View.GetCallbacks()
	debug.Sql = outerSql
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       outerEngine.DB,
		Debug:    debug,
		Context:  outerEngine.Context,
	}
	ColumnSchemaMap := make(map[string]*common.ColumnSchema)
	for _, ColumnSchema := range outerEngine.ColumnSchemas {
		ColumnSchemaMap[ColumnSchema.Name] = ColumnSchema
	}
	params := &client.QueryParams{
		Sql:             outerSql,
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

func (e *CHEngine) TransSelect(tags sqlparser.SelectExprs) error {
	tagSlice := []string{}
	for _, tag := range tags {
		item, ok := tag.(*sqlparser.AliasedExpr)
		if ok {
			colName, ok := item.Expr.(*sqlparser.ColName)
			if ok {
				tagSlice = append(tagSlice, sqlparser.String(colName))
			}
			funcName, ok := item.Expr.(*sqlparser.FuncExpr)
			if ok {
				tagSlice = append(tagSlice, sqlparser.String(funcName))
			}
		}
	}
	// tap_port and tap_port_type must exist together in select
	if common.IsValueInSliceString("tap_port", tagSlice) && !common.IsValueInSliceString("tap_port_type", tagSlice) && !common.IsValueInSliceString("enum(tap_port_type)", tagSlice) {
		return errors.New("tap_port and tap_port_type must exist together in select")
	}

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
				// pod_ingress/lb_listener is not supported by select
				if strings.HasPrefix(sqlparser.String(colName), "pod_ingress") || strings.HasPrefix(sqlparser.String(colName), "lb_listener") {
					errStr := fmt.Sprintf("%s is not supported by select", sqlparser.String(colName))
					return errors.New(errStr)
				} else if sqlparser.String(colName) == "tags" || sqlparser.String(colName) == "metrics" || sqlparser.String(colName) == "attributes" || sqlparser.String(colName) == "packet_batch" {
					if as != "" {
						errStr := fmt.Sprintf("%s does not support as", sqlparser.String(colName))
						return errors.New(errStr)
					}
				}
				if as != "" {
					e.asTagMap[as] = chCommon.ParseAlias(colName)
				}
			}
			function, ok := item.Expr.(*sqlparser.FuncExpr)
			if ok {
				if as != "" {
					e.asTagMap[as] = strings.Trim(sqlparser.String(function.Name), "`")
				}
			}
			binary, ok := item.Expr.(*sqlparser.BinaryExpr)
			if ok {
				if as != "" {
					e.asTagMap[as] = sqlparser.String(binary)
				}
			}
			// Integer tag
			val, ok := item.Expr.(*sqlparser.SQLVal)
			if ok {
				if as != "" {
					e.asTagMap[as] = sqlparser.String(val)
				}
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
				interval, err := chCommon.GetDatasourceInterval(e.DB, e.Table, e.DataSource)
				if err != nil {
					log.Error(err)
				}
				e.Model.Time.DatasourceInterval = interval
			} else {
				e.AddTable(fmt.Sprintf("%s.`%s`", e.DB, table))
			}
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
	groupSlice := []string{}
	for _, group := range groups {
		colName, ok := group.(*sqlparser.ColName)
		if ok {
			groupTag := sqlparser.String(colName)
			preAsGroup, ok := e.asTagMap[groupTag]
			if ok {
				groupSlice = append(groupSlice, preAsGroup)
			} else {
				groupSlice = append(groupSlice, groupTag)
			}
		}
		funcName, ok := group.(*sqlparser.FuncExpr)
		if ok {
			groupTag := sqlparser.String(funcName)
			preAsGroup, ok := e.asTagMap[groupTag]
			if ok {
				groupSlice = append(groupSlice, preAsGroup)
			} else {
				groupSlice = append(groupSlice, groupTag)
			}
		}
	}
	// tap_port and tap_port_type must exist together in group
	if common.IsValueInSliceString("tap_port", groupSlice) && !common.IsValueInSliceString("tap_port_type", groupSlice) && !common.IsValueInSliceString("enum(tap_port_type)", groupSlice) {
		return errors.New("tap_port and tap_port_type must exist together in group")
	}
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
		FormatLimit(e.Model)
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
		// pod_ingress/lb_listener is not supported by group
		if strings.HasPrefix(groupTag, "pod_ingress") || strings.HasPrefix(groupTag, "lb_listener") {
			errStr := fmt.Sprintf("%s is not supported by group", groupTag)
			return errors.New(errStr)
		}
		err := e.AddGroup(groupTag)
		if err != nil {
			return err
		}
		preAsGroup, ok := e.asTagMap[groupTag]
		if !ok {
			err := e.AddTag(groupTag, "")
			if err != nil {
				return err
			}
		} else {
			// pod_ingress/lb_listener is not supported by group
			if strings.HasPrefix(preAsGroup, "pod_ingress") || strings.HasPrefix(preAsGroup, "lb_listener") {
				errStr := fmt.Sprintf("%s is not supported by group", groupTag)
				return errors.New(errStr)
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
		e.ColumnSchemas = append(e.ColumnSchemas, common.NewColumnSchema(as, strings.ReplaceAll(chCommon.ParseAlias(item.Expr), "`", "")))
	} else {
		e.ColumnSchemas = append(e.ColumnSchemas, common.NewColumnSchema(strings.ReplaceAll(chCommon.ParseAlias(item.Expr), "`", ""), ""))
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
			if as == "" {
				as = strings.ReplaceAll(chCommon.ParseAlias(item.Expr), "`", "")
			}
			binFunction, err := e.parseSelectBinaryExpr(expr)
			if err != nil {
				return err
			}
			binFunction.SetAlias(as)
			e.Statements = append(e.Statements, binFunction)
			return nil
		}
		if e.DB == chCommon.DB_NAME_EXT_METRICS || e.DB == chCommon.DB_NAME_DEEPFLOW_SYSTEM {
			funcName := strings.Trim(sqlparser.String(expr.Name), "`")
			if _, ok := metrics.METRICS_FUNCTIONS_MAP[funcName]; ok {
				if as == "" {
					as = strings.ReplaceAll(chCommon.ParseAlias(item.Expr), "`", "")
				}
				args := []Function{}
				for _, arg := range expr.Exprs {
					arg, err := e.parseSelectBinaryExpr(arg.(*sqlparser.AliasedExpr).Expr)
					if err != nil {
						return err
					}
					args = append(args, arg)
				}
				binFunction, _ := GetBinaryFunc(funcName, args)
				binFunction.SetAlias(as)
				e.Statements = append(e.Statements, binFunction)
				e.ColumnSchemas[len(e.ColumnSchemas)-1].Type = common.COLUMN_SCHEMA_TYPE_METRICS
				return nil
			}
		}
		name, args, err := e.parseFunction(expr)
		if err != nil {
			return err
		}
		name = strings.Trim(name, "`")
		functionAs := as
		if as == "" {
			functionAs = strings.ReplaceAll(chCommon.ParseAlias(item.Expr), "`", "")
		}
		function, levelFlag, unit, err := GetAggFunc(name, args, functionAs, e.DB, e.Table, e.Context)
		if err != nil {
			return err
		}
		if function != nil {
			// 通过metric判断view是否拆层
			e.SetLevelFlag(levelFlag)
			e.Statements = append(e.Statements, function)
			e.ColumnSchemas[len(e.ColumnSchemas)-1].Type = common.COLUMN_SCHEMA_TYPE_METRICS
			if unit != "" {
				e.ColumnSchemas[len(e.ColumnSchemas)-1].Unit = unit
			}
			return nil
		}
		args[0] = strings.Trim(args[0], "`")
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
		if as == "" {
			as = strings.ReplaceAll(chCommon.ParseAlias(item.Expr), "`", "")
		}
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
		name = strings.Trim(name, "`")
		if err != nil {
			return nil, err
		}
		aggfunction, levelFlag, unit, err := GetAggFunc(name, args, "", e.DB, e.Table, e.Context)
		if err != nil {
			return nil, err
		}
		if aggfunction != nil {
			// 通过metric判断view是否拆层
			e.SetLevelFlag(levelFlag)
			e.ColumnSchemas[len(e.ColumnSchemas)-1].Type = common.COLUMN_SCHEMA_TYPE_METRICS
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
		metricStruct, ok := metrics.GetMetrics(field, e.DB, e.Table, e.Context)
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
	stmt, err = GetMetricsTag(tag, alias, e.DB, e.Table, e.Context)
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
				metricStruct, ok := metrics.GetMetrics(whereTag, e.DB, e.Table, e.Context)
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

func FormatModel(m *view.Model) {
	FormatInnerTime(m)
	FormatLimit(m)
}

func FormatLimit(m *view.Model) {
	if m.Limit.Limit == "" {
		defaultLimit := DEFAULT_LIMIT
		if config.Cfg != nil {
			defaultLimit = config.Cfg.Limit
		}
		m.Limit.Limit = defaultLimit
	}
}
