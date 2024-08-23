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
	"os"
	"strings"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	migsource "github.com/deepflowio/deepflow/server/controller/db/mysql/migrator/source"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator/source/script"
)

var log = logging.MustGetLogger("db.mysql.migrator.common")

type DBConfig struct {
	DB     *gorm.DB
	Config config.MySqlConfig
}

func NewDBConfig(db *gorm.DB, cfg config.MySqlConfig) *DBConfig {
	return &DBConfig{
		DB:     db,
		Config: cfg,
	}
}

func (dc *DBConfig) SetDB(db *gorm.DB) {
	dc.DB = db
}

func (dc *DBConfig) SetConfig(c config.MySqlConfig) {
	dc.Config = c
}

func LogDBName(databaseName string, format string, a ...any) string { // TODO use log prefix
	return fmt.Sprintf("[DB-%s] ", databaseName) + fmt.Sprintf(format, a...)
}

func DropDatabase(dc *DBConfig) error {
	log.Infof(LogDBName(dc.Config.Database, "drop database"))
	var databaseName string
	dc.DB.Raw(fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='%s'", dc.Config.Database)).Scan(&databaseName)
	if databaseName == dc.Config.Database {
		return dc.DB.Exec(fmt.Sprintf("DROP DATABASE %s", dc.Config.Database)).Error
	} else {
		log.Infof(LogDBName(dc.Config.Database, "database doesn't exist"))
		return nil
	}
}

func CreateDatabase(dc *DBConfig) error {
	log.Infof(LogDBName(dc.Config.Database, "create database"))
	return dc.DB.Exec(fmt.Sprintf("CREATE DATABASE %s", dc.Config.Database)).Error
}

func CreateDatabaseIfNotExists(dc *DBConfig) (bool, error) {
	var databaseName string
	dc.DB.Raw(fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='%s'", dc.Config.Database)).Scan(&databaseName)
	if databaseName == dc.Config.Database {
		return true, nil
	} else {
		err := CreateDatabase(dc)
		return false, err
	}
}

func CheckCEDBVersion(db *gorm.DB, name string) error {
	version, err := GetCEDBVersion(db)
	if err != nil {
		log.Error(LogDBName(name, "failed to get db version: %s", name, err.Error()))
		return nil
	}
	if version != migsource.DB_VERSION_EXPECTED {
		log.Error(LogDBName(name, "current db version: %s != expected db version: %s", name, version, migsource.DB_VERSION_EXPECTED))
		return err
	}
	return nil
}

func GetCEDBVersion(db *gorm.DB) (string, error) {
	var version string
	err := db.Raw(fmt.Sprintf("SELECT version FROM %s", migsource.DB_VERSION_TABLE)).Scan(&version).Error
	return version, err
}

func InitCETables(dc *DBConfig) error {
	log.Info(LogDBName(dc.Config.Database, "initialize CE tables"))

	// 先初始化所有组织需要的 CE 表，再判断数据库是否是 default 组织，如果是 default 组织，初始化仅 default 组织所需数据。
	err := initCEORGTables(dc)
	if err != nil {
		return err
	}

	// 通过判断数据库名称后缀，判断数据库是否是 default 组织。
	if !strings.HasSuffix(dc.Config.Database, common.NON_DEFAULT_ORG_DATABASE_SUFFIX) {
		if err := initCEDefaultORGTables(dc); err != nil {
			return err
		}
	}

	err = initCEDBVersion(dc)
	if err != nil {
		return err
	}

	log.Info(LogDBName(dc.Config.Database, "initialized CE tables successfully"))
	return nil
}

func initCEORGTables(dc *DBConfig) error {
	log.Info(LogDBName(dc.Config.Database, "initialize CE org tables"))
	initSQL, err := os.ReadFile(fmt.Sprintf("%s/init.sql", SQL_FILE_DIR))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read CE org sql file: %s", err.Error()))
		return err
	}
	err = dc.DB.Exec(string(initSQL)).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to initialize CE org tables: %s", err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "initialized CE org tables successfully"))
	return nil
}

func initCEDefaultORGTables(dc *DBConfig) error {
	log.Info(LogDBName(dc.Config.Database, "initialize CE default org tables"))
	initSQL, err := os.ReadFile(fmt.Sprintf("%s/default_init.sql", SQL_FILE_DIR))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read CE default org sql file: %s", err.Error()))
		return err
	}
	err = dc.DB.Exec(string(initSQL)).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to initialize CE default org tables: %s", err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "initialized CE default org tables successfully"))
	return nil
}

func initCEDBVersion(dc *DBConfig) error {
	err := dc.DB.Exec(fmt.Sprintf("INSERT INTO %s (version) VALUE ('%s')", migsource.DB_VERSION_TABLE, migsource.DB_VERSION_EXPECTED)).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to initialize db version: %s", err.Error()))
	}
	return err
}

func ExecuteIssues(dc *DBConfig, curVersion string) error {
	issus, err := os.ReadDir(fmt.Sprintf("%s/issu", SQL_FILE_DIR))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read sql dir: %s", err.Error()))
		return err
	}
	nextVersions := getAscSortedNextVersions(issus, curVersion)
	log.Info(LogDBName(dc.Config.Database, "issues to be executed: %v", nextVersions))
	for _, nv := range nextVersions {
		err = executeIssue(dc, nv)
		if err != nil {
			return err
		}
		err = executeScript(dc, nv)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeIssue(dc *DBConfig, nextVersion string) error {
	byteSQL, err := os.ReadFile(fmt.Sprintf("%s/issu/%s.sql", SQL_FILE_DIR, nextVersion))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read sql file (version: %s): %s", nextVersion, err.Error()))
		return err
	}
	if len(byteSQL) == 0 {
		log.Warning(LogDBName(dc.Config.Database, "issue with no content (version: %s)", nextVersion))
		return nil
	}

	strSQL := fmt.Sprintf("SET @defaultDatabaseName='%s';\n", "deepflow") + string(byteSQL) // TODO use config
	err = dc.DB.Exec(strSQL).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to execute db issue (version: %s): %s", nextVersion, err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "executed db issue (version: %s) successfully", nextVersion))
	return nil
}

func executeScript(dc *DBConfig, nextVersion string) error {
	var err error
	switch nextVersion {
	case script.SCRIPT_UPDATE_CLOUD_TAG:
		err = script.ScriptUpdateCloudTags(dc.DB)
	case script.SCRIPT_UPDATE_VM_PODNS_TAG:
		err = script.ScriptUpdateVMPodNSTags(dc.DB)
	}
	return err
}
