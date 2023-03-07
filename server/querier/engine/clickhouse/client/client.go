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

package client

import (
	"context"
	//"database/sql"
	"fmt"
	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/jmoiron/sqlx"
	//"github.com/k0kubun/pp"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/statsd"
	"github.com/google/uuid"
	logging "github.com/op/go-logging"
	"github.com/signalfx/splunk-otel-go/instrumentation/github.com/jmoiron/sqlx/splunksqlx"
	"time"
	"unsafe"
)

var log = logging.MustGetLogger("clickhouse.client")

type QueryParams struct {
	Sql             string
	Callbacks       map[string]func(result *common.Result) error
	QueryUUID       string
	ColumnSchemaMap map[string]*common.ColumnSchema
}

type Client struct {
	Host       string
	Port       int
	UserName   string
	Password   string
	connection *sqlx.DB
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
	url := fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s?&query_id=%s", c.UserName, c.Password, c.Host, c.Port, c.DB, query_uuid)
	conn, err := splunksqlx.Open("clickhouse", url)
	if err != nil {
		log.Errorf("connect clickhouse failed: %s, url: %s, query_uuid: %s", err, url, query_uuid)
		return err
	}
	c.connection = conn
	return nil
}

func (c *Client) Close() error {
	return c.connection.Close()
}

func (c *Client) DoQuery(params *QueryParams) (result *common.Result, err error) {
	sqlstr, callbacks, query_uuid, columnSchemaMap := params.Sql, params.Callbacks, params.QueryUUID, params.ColumnSchemaMap
	err = c.init(query_uuid)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	start := time.Now()
	var rows *sqlx.Rows
	if c.Context != nil {
		rows, err = c.connection.QueryxContext(c.Context, sqlstr)
	} else {
		rows, err = c.connection.Queryx(sqlstr)
	}

	c.Debug.Sql = sqlstr
	if err != nil {
		log.Errorf("query clickhouse Error: %s, sql: %s, query_uuid: %s", err, sqlstr, c.Debug.QueryUUID)
		c.Debug.Error = fmt.Sprintf("%s", err)
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.ColumnTypes()
	resColumns := len(columns)
	if err != nil {
		c.Debug.Error = fmt.Sprintf("%s", err)
		return nil, err
	}
	columnNames := make([]interface{}, 0, len(columns))
	columnTypes := make([]string, 0, len(columns))
	var columnSchemas common.ColumnSchemas
	// 获取列名和列类型
	for _, column := range columns {
		columnNames = append(columnNames, column.Name())
		columnTypes = append(columnTypes, column.DatabaseTypeName())
		if schema, ok := columnSchemaMap[column.Name()]; ok {
			columnSchemas = append(columnSchemas, schema)
		} else {
			columnSchemas = append(columnSchemas, common.NewColumnSchema(column.Name(), ""))
		}
	}
	var values []interface{}
	resSize := 0
	for rows.Next() {
		// row, err := rows.SliceScan()
		var row []interface{}
		row, err = sqlx.SliceScan(rows)
		if err != nil {
			c.Debug.Error = fmt.Sprintf("%s", err)
			return nil, err
		}
		record := make([]interface{}, 0, len(row))
		for i, rawValue := range row {
			value, valueType, err := TransType(columnTypes[i], rawValue)
			if err != nil {
				c.Debug.Error = fmt.Sprintf("%s", err)
				return nil, err
			}
			resSize += int(unsafe.Sizeof(value))
			record = append(record, value)
			columnSchemas[i].ValueType = valueType
		}
		values = append(values, record)
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
	c.Debug.QueryTime = int64(queryTime)
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
	log.Debugf("sql: %s, query_uuid: %s", sqlstr, c.Debug.QueryUUID)
	log.Infof("res_rows: %v, res_columns: %v, res_size: %v", resRows, resColumns, resSize)
	return result, nil
}
