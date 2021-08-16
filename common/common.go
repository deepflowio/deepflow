package common

import (
	"database/sql"
	"fmt"

	clickhouse "github.com/ClickHouse/clickhouse-go"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("common")

func NewCKConnection(addr, username, password string) (*sql.DB, error) {
	connect, err := sql.Open("clickhouse", fmt.Sprintf("%s?username=%s&password=%s", addr, username, password))
	if err != nil {
		return nil, err
	}
	if err := connect.Ping(); err != nil {
		if exception, ok := err.(*clickhouse.Exception); ok {
			log.Warningf("[%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		}
		return nil, err
	}
	return connect, nil
}
