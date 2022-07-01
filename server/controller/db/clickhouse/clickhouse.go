package clickhouse

import (
	"fmt"

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
	url := fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s", cfg.UserName, cfg.UserPassword, cfg.Host, cfg.Port, "default")
	Db, err := sqlx.Open(
		"clickhouse", url,
	)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return Db, nil
}
