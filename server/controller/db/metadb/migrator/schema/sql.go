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

package schema

import (
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/schema/rawsql/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/schema/rawsql/postgres"
)

var log = logging.MustGetLogger("db.metadb.migrator.schema")

type SqlFmt interface {
	SetConfig(config.Config)
	GetRawSqlFileDir() string
	CreateDatabase() string
	DropDatabase() string
	SelectDatabase() string
	SelectTable(string) string
	SelectColumn(tableName, columnName string) string
	InsertDBVersion(tableName, version string) string
}

func GetSqlFmt(cfg config.Config) SqlFmt {
	var r SqlFmt
	switch cfg.Type {
	case config.MetaDBTypeMySQL:
		r = &mysql.SqlFmt{}
	case config.MetaDBTypePostgreSQL:
		r = &postgres.SqlFmt{}
	default:
		log.Errorf("unsupported database type: %s", cfg.Type)
		return nil
	}
	r.SetConfig(cfg)
	return r
}
