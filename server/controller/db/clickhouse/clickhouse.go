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

package clickhouse

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("db.clickhouse")
var Db *sqlx.DB

type ClickHouseConfig struct {
	Database     string `default:"flow_tag" yaml:"database"`
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
