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

package session

import (
	"database/sql"
	"database/sql/driver"
	"fmt"

	postgres_driver "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
)

func getPostgreSQLConnector(cfg config.SessionConfig) (driver.Connector, error) {
	connStr := "user=" + cfg.DBCfg.UserName +
		" password=" + cfg.DBCfg.UserPassword +
		" host=" + cfg.DBCfg.Host +
		" port=" + fmt.Sprintf("%d", cfg.DBCfg.Port) +
		" connect_timeout=" + fmt.Sprintf("%d", cfg.TimeoutCoefficient*cfg.DBCfg.TimeOut) +
		" sslmode=disable" +
		" client_encoding=UTF8"

	database := "postgres" // TODO
	if cfg.UseDabase {
		database = cfg.DBCfg.Database
	}
	connStr += " dbname=" + database +
		" search_path=" + cfg.DBCfg.Schema

	connector, err := postgres_driver.NewConnector(connStr)
	if err != nil {
		log.Error("get database(%s) connector failed with error: %v", database, err.Error())
		return nil, err
	}
	return connector, nil
}

func getPostgresDialector(conn driver.Connector) gorm.Dialector {
	return postgres.New(postgres.Config{
		Conn: sql.OpenDB(conn),
	})
}
