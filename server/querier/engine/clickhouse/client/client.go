/*
 * Copyright (c) 2024 Yunshan Networks
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

package client

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	//"github.com/k0kubun/pp"

	ctrCommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/statsd"
	"github.com/google/uuid"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("clickhouse.client")

type QueryParams struct {
	Sql             string
	UseQueryCache   bool
	QueryCacheTTL   string
	Callbacks       map[string]func(result *common.Result) error
	QueryUUID       string
	ColumnSchemaMap map[string]*common.ColumnSchema
	ORGID           string
	SimpleSql       bool
}

// All ClickHouse Client share one connection
var connection clickhouse.Conn
var version string

type Client struct {
	Host       string
	Port       int
	UserName   string
	Password   string
	connection clickhouse.Conn
	DB         string
	Context    context.Context
	Debug      *Debug
}

func (c *Client) init(query_uuid string) error {
	if query_uuid == "" {
		query_uuid = uuid.NewString()
	}
	if c.Debug == nil {
		c.Debug = &Debug{
			QueryUUID: query_uuid,
			IP:        c.Host,
		}
	}
	if connection == nil { // FIXME: add a RWLock
		conn, err := clickhouse.Open(&clickhouse.Options{
			Addr: []string{net.JoinHostPort(c.Host, strconv.Itoa(c.Port))},
			Auth: clickhouse.Auth{
				Database: "default",
				Username: c.UserName,
				Password: c.Password,
			},
			// Default MaxOpenConns = MaxIdleConns + 5
			//     Ref: https://clickhouse.com/docs/en/integrations/go/clickhouse-go/clickhouse-api#connection-settings
			// In ClickHouse SDK, when returning a connection, if the current number of idle connections is equal to
			// `MaxIdleConns`, the connection to be returned will be closed directly. Therefore, when `MaxOpenConns`
			// is greater than `MaxIdleConns`, it is very easy for the connection to be actively closed, and it is
			// easy to cause a lot of short connections during high-concurrency queries, so set the two to the same
			// value here.
			//     Ref: https://github.com/ClickHouse/clickhouse-go/blob/main/clickhouse.go#L296
			MaxOpenConns: config.Cfg.Clickhouse.MaxConnection,
			MaxIdleConns: config.Cfg.Clickhouse.MaxConnection,
			DialTimeout:  time.Duration(config.Cfg.Clickhouse.Timeout) * time.Second,
		})
		if err != nil {
			log.Errorf("connect clickhouse failed: %s, url: %s:%s@%s:%d", err, c.UserName, c.Password, c.Host, c.Port)
			return err
		}
		connection = conn
	}
	c.connection = connection
	if version == "" {
		version, _ = c.GetVersion()
	}
	return nil
}

func (c *Client) Close() error {
	return nil
}

func (c *Client) DoQuery(params *QueryParams) (result *common.Result, err error) {
	sqlstr, callbacks, query_uuid, columnSchemaMap, simpleSql := params.Sql, params.Callbacks, params.QueryUUID, params.ColumnSchemaMap, params.SimpleSql
	queryCacheStr := ""
	if params.UseQueryCache {
		queryCacheStr = " SETTINGS use_query_cache = true"
		if version > ctrCommon.CLICK_HOUSE_VERSION {
			queryCacheStr += ", query_cache_nondeterministic_function_handling = 'save'"
		} else {
			queryCacheStr += ", query_cache_store_results_of_queries_with_nondeterministic_functions = 1"
		}
		if params.QueryCacheTTL != "" {
			queryCacheStr += fmt.Sprintf(", query_cache_ttl = %s", params.QueryCacheTTL)
		}
		sqlstr += queryCacheStr
	}
	// ORGID
	if !simpleSql && params.ORGID != common.DEFAULT_ORG_ID && params.ORGID != "" {
		orgIDInt, err := strconv.Atoi(params.ORGID)
		if err != nil {
			return nil, err
		}
		sqlstr = strings.ReplaceAll(sqlstr, "flow_tag", fmt.Sprintf("%04d_flow_tag", orgIDInt))
	}
	// live view
	if version > ctrCommon.CLICK_HOUSE_VERSION {
		sqlstr = strings.ReplaceAll(sqlstr, "app_label_live_view", "app_label_map")
		sqlstr = strings.ReplaceAll(sqlstr, "target_label_live_view", "target_label_map")
	}

	err = c.init(query_uuid)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	start := time.Now()
	ctx := c.Context
	if c.Context == nil {
		ctx = context.Background()
	}
	rows, err := c.connection.Query(ctx, sqlstr)
	c.Debug.Sql = sqlstr
	if err != nil {
		log.Errorf("query clickhouse Error: %s, sql: %s, query_uuid: %s", err, sqlstr, c.Debug.QueryUUID)
		c.Debug.Error = fmt.Sprintf("%s", err)
		return nil, err
	}
	defer rows.Close()
	columns := rows.ColumnTypes()
	resColumns := len(columns)
	columnNames := make([]interface{}, 0, len(columns))
	var columnSchemas common.ColumnSchemas // FIXME: Slice growth should be avoided.
	// 获取列名和列类型
	for _, column := range columns {
		columnNames = append(columnNames, column.Name())
		if schema, ok := columnSchemaMap[column.Name()]; ok {
			columnSchemas = append(columnSchemas, schema)
		} else {
			columnSchemas = append(columnSchemas, common.NewColumnSchema(column.Name(), "", ""))
		}
	}
	var values []interface{}
	columnValues := make([]interface{}, len(columns))
	for i := range columns {
		columnValues[i] = reflect.New(columns[i].ScanType()).Interface()
		columnSchemas[i].ValueType = columns[i].DatabaseTypeName()
	}
	resSize := 0
	for rows.Next() {
		if err := rows.Scan(columnValues...); err != nil {
			c.Debug.Error = fmt.Sprintf("%s", err)
			return nil, err
		}
		record := make([]interface{}, 0, len(columns))
		for _, rawValue := range columnValues {
			value := TransType(rawValue)
			resSize += int(unsafe.Sizeof(value))
			record = append(record, value)
		}
		values = append(values, record)
	}
	// Even if the query operation produces an error, it does not necessarily return an error in the'err 'parameter,
	// so the return value of the'rows. Err () ' method must be checked to ensure that the query operation is successful
	if err := rows.Err(); err != nil {
		log.Errorf("query clickhouse Error: %s, sql: %s, query_uuid: %s", err, sqlstr, c.Debug.QueryUUID)
		c.Debug.Error = fmt.Sprintf("%s", err)
		return nil, err
	}
	queryTime := time.Since(start)
	resRows := len(values)
	statsd.QuerierCounter.WriteCk(
		&statsd.ClickhouseCounter{
			ResponseSize: uint64(resSize),
			RowCount:     uint64(resRows),
			ColumnCount:  uint64(resColumns),
			QueryTime:    uint64(queryTime),
		},
	)
	c.Debug.QueryTime = fmt.Sprintf("%.9fs", float64(queryTime)/1e9)
	result = &common.Result{
		Columns: columnNames,
		Values:  values,
		Schemas: columnSchemas,
	}
	for _, callback := range callbacks {
		err := callback(result)
		if err != nil {
			log.Error("Execute Callback %v Error: %v", callback, err)
		}
	}
	log.Infof("query_uuid: %s. query api statistics: %d rows, %d columns, %d bytes, cost %f ms", c.Debug.QueryUUID, resRows, resColumns, resSize, float64(queryTime.Milliseconds()))
	return result, nil
}

func (c *Client) GetVersion() (version string, err error) {
	defer c.Close()
	ctx := c.Context
	if c.Context == nil {
		ctx = context.Background()
	}
	sqlstr := "SELECT version()"
	rows, err := c.connection.Query(ctx, sqlstr)
	if err != nil {
		log.Errorf("query clickhouse Error: %s, sql: %s", err, sqlstr)
		return
	}
	defer rows.Close()
	columns := rows.ColumnTypes()
	columnNames := make([]interface{}, 0, len(columns))
	// 获取列名和列类型
	for _, column := range columns {
		columnNames = append(columnNames, column.Name())
	}
	columnValues := make([]interface{}, len(columns))
	for i := range columns {
		columnValues[i] = reflect.New(columns[i].ScanType()).Interface()
	}
	for rows.Next() {
		if err = rows.Scan(columnValues...); err != nil {
			return
		}
		for _, rawValue := range columnValues {
			value := TransType(rawValue)
			version, _ = value.(string)
			log.Infof("database version is %s", version)
			return
		}
	}
	// Even if the query operation produces an error, it does not necessarily return an error in the'err 'parameter,
	// so the return value of the'rows. Err () ' method must be checked to ensure that the query operation is successful
	if err = rows.Err(); err != nil {
		log.Errorf("query clickhouse Error: %s, sql: %s", err, sqlstr)
		return
	}
	return
}
