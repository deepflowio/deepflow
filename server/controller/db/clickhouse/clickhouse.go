package clickhouse

import (
	"fmt"
	"strconv"

	_ "github.com/ClickHouse/clickhouse-go"
	"github.com/jmoiron/sqlx"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("db.clickhouse")
var Db *sqlx.DB

type ClickHouseConfig struct {
	Database     string `default:"deepflow" yaml:"database"`
	Host         string `default:"clickhouse" yaml:"host"`
	Port         uint32 `default:"9000" yaml:"port"`
	UserName     string `default:"default" yaml:"user-name"`
	UserPassword string `default:"" yaml:"user-password"`
	TimeOut      uint32 `default:"30" yaml:"timeout"`
}

func Connect(cfg ClickHouseConfig) (*sqlx.DB, error) {
	portStr := strconv.Itoa(int(cfg.Port))
	Db, err := sqlx.Open("clickhouse", fmt.Sprintf("tcp://%s:%s?username=%s&password=%s", cfg.Host, portStr, cfg.UserName, cfg.UserPassword))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return Db, nil
}
