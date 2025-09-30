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
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/schema"
)

func CheckCEDBVersion(dc *DBConfig) error {
	return CheckDBVersion(dc, schema.DB_VERSION_TABLE, schema.DB_VERSION_EXPECTED)
}

func GetCEDBVersion(dc *DBConfig) (string, error) {
	return GetDBVersion(dc, schema.DB_VERSION_TABLE)
}

func CheckCEDBVersionTableExists(dc *DBConfig) (bool, error) {
	return CheckTableExists(dc, schema.DB_VERSION_TABLE)
}

func CheckDBVersion(dc *DBConfig, tableName string, expectedVersion string) error {
	version, err := GetDBVersion(dc, tableName)
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to get %s: %s", tableName, err.Error()))
		return err
	}
	if version != expectedVersion {
		log.Error(LogDBName(dc.Config.Database, "%s current version: %s != expected version: %s", tableName, version, expectedVersion))
		return fmt.Errorf("%s current version: %s != expected version: %s", tableName, version, expectedVersion)
	}
	return nil
}

func GetDBVersion(dc *DBConfig, tableName string) (string, error) {
	var version string
	err := dc.DB.Raw(dc.SqlFmt.SelectColumn(tableName, "version")).Scan(&version).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to get %s: %s", tableName, err.Error()))
		return "", err
	}
	return version, err
}

func CheckTableExists(dc *DBConfig, tableName string) (bool, error) {
	var table string
	err := dc.DB.Raw(dc.SqlFmt.SelectTable(tableName)).Scan(&table).Error

	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to check table %s exists: %s", tableName, err.Error()))
		return false, err
	}
	return table == tableName, nil
}

func InsertDBVersion(dc *DBConfig, tableName string, version string) error {
	log.Info(LogDBName(dc.Config.Database, "insert %s: %s", tableName, version))
	err := dc.DB.Exec(dc.SqlFmt.InsertDBVersion(tableName, version)).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to insert %s: %s", tableName, err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "inserted %s: %s successfully", tableName, version))
	return nil
}

func InitDBVersionTable(dc *DBConfig, rawSqlDir string) error {
	return ReadAndExecuteSqlFile(dc, GetDBVersionDDLFile(rawSqlDir))
}
