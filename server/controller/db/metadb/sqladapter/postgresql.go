/*
 * Copyright (c) 2025 Yunshan Networks
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

package sqladapter

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
)

type PostgreSQLAdapter struct {
	cfg config.Config
}

func (f *PostgreSQLAdapter) SetConfig(cfg config.Config) {
	f.cfg = cfg
}

func (f *PostgreSQLAdapter) GetRawSqlDirectory(parentDir string) string {
	return parentDir + "/postgres"
}

func (f *PostgreSQLAdapter) CreateDatabase() string {
	return fmt.Sprintf("CREATE DATABASE %s", f.cfg.Database)
}

func (f *PostgreSQLAdapter) DropDatabase() string {
	return fmt.Sprintf("DROP DATABASE IF EXISTS %s", f.cfg.Database)
}

func (f *PostgreSQLAdapter) SelectDatabase() string {
	return fmt.Sprintf("SELECT datname FROM pg_catalog.pg_database WHERE datname='%s'", f.cfg.Database)
}

func (f *PostgreSQLAdapter) SelectTable(tableName string) string {
	return fmt.Sprintf("SELECT table_name FROM information_schema.tables WHERE table_catalog='%s' AND table_schema='%s' AND table_name='%s'", f.cfg.Database, f.cfg.Schema, tableName)
}

func (f *PostgreSQLAdapter) SelectColumn(tableName, columnName string) string {
	return fmt.Sprintf("SELECT %s FROM %s", columnName, tableName)
}

func (f *PostgreSQLAdapter) InsertDBVersion(tableName, version string) string {
	return fmt.Sprintf("INSERT INTO %s (version) VALUES ('%s')", tableName, version)
}
