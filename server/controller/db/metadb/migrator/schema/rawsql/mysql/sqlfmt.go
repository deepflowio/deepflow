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

package mysql

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
)

type SqlFmt struct {
	cfg config.Config
}

func (f *SqlFmt) SetConfig(cfg config.Config) {
	f.cfg = cfg
}

func (f *SqlFmt) GetRawSqlFileDir() string {
	return "/etc/metadb/schema/rawsql/mysql"
}

func (f *SqlFmt) CreateDatabase() string {
	return fmt.Sprintf("CREATE DATABASE %s", f.cfg.Database)
}

func (f *SqlFmt) DropDatabase() string {
	return fmt.Sprintf("DROP DATABASE IF EXISTS %s", f.cfg.Database)
}

func (f *SqlFmt) SelectDatabase() string {
	return fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='%s'", f.cfg.Database)
}

func (f *SqlFmt) SelectTable(tableName string) string {
	return fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", f.cfg.Database, tableName)
}

func (f *SqlFmt) SelectColumn(tableName, columnName string) string {
	return fmt.Sprintf("SELECT %s FROM %s", columnName, tableName)
}

func (f *SqlFmt) InsertDBVersion(tableName, version string) string {
	return fmt.Sprintf("INSERT INTO %s (version) VALUES ('%s')", tableName, version)
}
