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

package common

import (
	"os"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/schema"
)

type EditionInitTablesFunc func(dc *DBConfig) error // TODO

func DropDatabaseIfInitTablesFailed(dc *DBConfig, editionFunc EditionInitTablesFunc) error {
	log.Info(LogDBName(dc.Config.Database, "drop database if fails to initialize tables"))
	err := editionFunc(dc)
	if err != nil {
		newErr := DropDatabase(dc)
		if newErr != nil {
			log.Error(LogDBName(dc.Config.Database, "failed to drop database: %s", newErr.Error()))
		}
		return err
	}
	return nil
}

func InitCETables(dc *DBConfig) error {
	err := InitTables(dc, dc.SqlFmt.GetRawSqlDirectory(schema.RAW_SQL_ROOT_DIR))
	if err != nil {
		return err
	}
	return InsertDBVersion(dc, schema.DB_VERSION_TABLE, schema.DB_VERSION_EXPECTED)
}

func InitTables(dc *DBConfig, rawSqlDir string) error {
	log.Info(LogDBName(dc.Config.Database, "initialize %s tables", rawSqlDir))

	for _, sqlFile := range GetSortedSQLFiles(rawSqlDir, false) {
		err := ReadAndExecuteSqlFile(dc, sqlFile)
		if err != nil {
			return err
		}
	}

	// 通过判断数据库名称后缀，判断数据库是否是 default 组织。
	if !strings.HasSuffix(dc.Config.Database, common.NON_DEFAULT_ORG_DATABASE_SUFFIX) {
		for _, sqlFile := range GetSortedSQLFiles(rawSqlDir, true) {
			err := ReadAndExecuteSqlFile(dc, sqlFile)
			if err != nil {
				return err
			}
		}
	}

	log.Info(LogDBName(dc.Config.Database, "initialized %s tables successfully", rawSqlDir))
	return nil
}

func ReadAndExecuteSqlFile(dc *DBConfig, sqlFile string) error {
	log.Info(LogDBName(dc.Config.Database, "execute %s", sqlFile))
	initSQL, err := os.ReadFile(sqlFile)
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read %s sql file: %s", sqlFile, err.Error()))
		return err
	}
	err = dc.DB.Exec(string(initSQL)).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to execute %s: %s", sqlFile, err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "executed %s successfully", sqlFile))
	return nil
}
