package client

import (
	"fmt"
	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/jmoiron/sqlx"
	//"github.com/k0kubun/pp"
	logging "github.com/op/go-logging"
	"time"
)

var log = logging.MustGetLogger("clickhouse.client")

type Client struct {
	Host       string
	Port       int
	UserName   string
	Password   string
	connection *sqlx.DB
	DB         string
	Debug      *Debug
}

func (c *Client) Init(query_uuid string) error {
	if c.Debug == nil {
		c.Debug = &Debug{
			QueryUUID: query_uuid,
			IP:        c.Host,
		}
	}
	url := fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s?&query_id=%s", c.UserName, c.Password, c.Host, c.Port, c.DB, query_uuid)
	conn, err := sqlx.Open(
		"clickhouse", url,
	)
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

func (c *Client) DoQuery(sql string, callbacks []func(columns []interface{}, values []interface{}) []interface{}) (map[string][]interface{}, error) {
	rows, err := c.connection.Queryx(sql)
	c.Debug.Sql = sql
	if err != nil {
		log.Errorf("query clickhouse Error: %s, sql: %s, query_uuid: %s", err, sql, c.Debug.QueryUUID)
		c.Debug.Error = fmt.Sprintf("%s", err)
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.ColumnTypes()
	if err != nil {
		c.Debug.Error = fmt.Sprintf("%s", err)
		return nil, err
	}
	result := make(map[string][]interface{})
	var columnNames []interface{}
	var columnTypes []string
	// 获取列名和列类型
	for _, column := range columns {
		columnNames = append(columnNames, column.Name())
		columnTypes = append(columnTypes, column.DatabaseTypeName())
	}
	result["columns"] = columnNames
	var values []interface{}
	start := time.Now()
	for rows.Next() {
		row, err := rows.SliceScan()
		if err != nil {
			c.Debug.Error = fmt.Sprintf("%s", err)
			return nil, err
		}
		var record []interface{}
		for i, rawValue := range row {
			value, err := TransType(columnTypes[i], rawValue)
			if err != nil {
				c.Debug.Error = fmt.Sprintf("%s", err)
				return nil, err
			}
			record = append(record, value)
		}
		values = append(values, record)
	}
	queryTime := time.Since(start)
	c.Debug.QueryTime = int64(queryTime)
	for _, callback := range callbacks {
		values = callback(columnNames, values)
	}
	result["values"] = values
	return result, nil
}
