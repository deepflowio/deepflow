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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration/script"
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

func LogDBName(databaseName string, format string, a ...any) string {
	return fmt.Sprintf("db: %s, ", databaseName) + fmt.Sprintf(format, a...)
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
	log.Infof("%#v", dc.DB)
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

func InitCETables(dc *DBConfig) error {
	log.Info(LogDBName(dc.Config.Database, "initialize CE tables"))
	log.Infof("%#v", dc.DB)
	initSQL, err := os.ReadFile(fmt.Sprintf("%s/init.sql", SQL_FILE_DIR))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read sql file: %s", err.Error()))
		return err
	}
	err = dc.DB.Exec(string(initSQL)).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to initialize db tables: %s", err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "initialized CE tables successfully"))
	return err
}

func InitDBVersion(dc *DBConfig) error {
	err := dc.DB.Exec(fmt.Sprintf("INSERT INTO db_version (version) VALUE ('%s')", migration.DB_VERSION_EXPECTED)).Error
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

	strSQL := fmt.Sprintf("SET @defaultDatabaseName='%s';\n", mysql.DefaultDB.Name) + string(byteSQL)
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

func getAscSortedNextVersions(files []fs.DirEntry, curVersion string) []string {
	vs := []string{}
	for _, f := range files {
		vs = append(vs, trimFilenameExt(f.Name()))
	}
	// asc sort: split version by ".", compare each number from first to end
	sort.Slice(vs, func(i, j int) bool {
		il := strings.Split(vs[i], ".")
		jl := strings.Split(vs[j], ".")
		return !list1GreaterList2(il, jl)
	})

	nvs := []string{}
	cvl := strings.Split(curVersion, ".")
	for _, v := range vs {
		vl := strings.Split(v, ".")
		if list1GreaterList2(vl, cvl) {
			nvs = append(nvs, v)
		}
	}
	return nvs
}

func trimFilenameExt(filename string) string {
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}

func list1GreaterList2(strList1, strList2 []string) bool {
	for i := range strList1 {
		if strList1[i] == strList2[i] {
			continue
		} else {
			in, _ := strconv.Atoi(strList1[i])
			jn, _ := strconv.Atoi(strList2[i])
			return in > jn
		}
	}
	return false
}
