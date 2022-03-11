package client

import (
	"fmt"
	_ "github.com/ClickHouse/clickhouse-go"
	"github.com/jmoiron/sqlx"
)

type Client struct {
	IP         string
	Port       string
	UserName   string
	Password   string
	connection *sqlx.DB
	DB         string
}

func (c *Client) Init() error {
	url := fmt.Sprintf("tcp://%s:%s?username=%s&password=%s", c.IP, c.Port, c.UserName, c.Password)
	if c.DB != "" {
		url = fmt.Sprintf("%s&database=%s", url, c.DB)
	}
	conn, err := sqlx.Open(
		"clickhouse", url,
	)
	if err != nil {
		return err
	}
	c.connection = conn
	return nil
}

func (c *Client) DoQuery(sql string) (map[string][]interface{}, error) {
	rows, err := c.connection.Queryx(sql)
	if err != nil {
		// TODO: log
		return nil, err
	}
	columns, err := rows.ColumnTypes()
	if err != nil {
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
	for rows.Next() {
		row, err := rows.SliceScan()
		if err != nil {
			return nil, err
		}
		var values []interface{}
		for i, rawValue := range row {
			value, err := TransType(columnTypes[i], rawValue)
			if err != nil {
				return nil, err
			}
			//TODO: callback
			values = append(values, value)
		}
		result["values"] = append(result["values"], values)
	}
	return result, nil
}
