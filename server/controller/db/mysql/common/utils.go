/*
 * Copyright (c) 2022 Yunshan Networks
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
	"io/ioutil"
	l "log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/op/go-logging"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	. "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
)

var log = logging.MustGetLogger("db.mysql.common")

var SQL_FILE_DIR = "/etc/mysql"

func GetConnectionWithoudDatabase(cfg MySqlConfig) *gorm.DB {
	dsn := GetDSN(cfg, "", cfg.TimeOut, false)
	return GetGormDB(dsn)
}

func GetConnectionWithDatabase(cfg MySqlConfig) *gorm.DB {
	// set multiStatements=true in dsn only when migrating MySQL
	dsn := GetDSN(cfg, cfg.Database, cfg.TimeOut*2, true)
	return GetGormDB(dsn)
}

func GetDSN(cfg MySqlConfig, database string, timeout uint32, multiStatements bool) string {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local&timeout=%ds",
		cfg.UserName,
		cfg.UserPassword,
		cfg.Host,
		cfg.Port,
		database,
		timeout,
	)
	if multiStatements {
		dsn += "&multiStatements=true"
	}
	return dsn
}

func GetGormDB(dsn string) *gorm.DB {
	Db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                       dsn,   // DSN data source name
		DefaultStringSize:         256,   // string 类型字段的默认长度
		DisableDatetimePrecision:  true,  // 禁用 datetime 精度，MySQL 5.6 之前的数据库不支持
		DontSupportRenameIndex:    true,  // 重命名索引时采用删除并新建的方式，MySQL 5.7 之前的数据库和 MariaDB 不支持重命名索引
		DontSupportRenameColumn:   true,  // 用 `change` 重命名列，MySQL 8 之前的数据库和 MariaDB 不支持重命名列
		SkipInitializeWithVersion: false, // 根据当前 MySQL 版本自动配置
	}), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true}, // 设置全局表名禁用复数
		Logger: logger.New(
			l.New(os.Stdout, "\r\n", l.LstdFlags), // io writer
			logger.Config{
				SlowThreshold:             0,            // 慢SQL阈值,为0时不打印
				LogLevel:                  logger.Error, // Log level
				IgnoreRecordNotFoundError: false,        // 忽略ErrRecordNotFound（记录未找到）错误
				Colorful:                  true,         // 是否彩色打印
			}), // 配置log
	})
	if err != nil {
		log.Errorf("Mysql Connection failed with error: %v", err.Error())
		return nil
	}

	sqlDB, _ := Db.DB()
	// 限制最大空闲连接数、最大连接数和连接的生命周期
	sqlDB.SetMaxIdleConns(50)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	return Db
}

func DropDatabase(db *gorm.DB, database string) error {
	log.Infof("drop database %s", database)
	return db.Exec(fmt.Sprintf("DROP DATABASE %s", database)).Error
}

func CreateDatabase(db *gorm.DB, database string) error {
	log.Infof("create database %s", database)
	return db.Exec(fmt.Sprintf("CREATE DATABASE %s", database)).Error
}

func CreateDatabaseIfNotExists(db *gorm.DB, database string) (bool, error) {
	var datadbaseName string
	db.Raw(fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='%s'", database)).Scan(&datadbaseName)
	if datadbaseName == database {
		return true, nil
	} else {
		err := CreateDatabase(db, database)
		return false, err
	}
}

func RollbackIfInitTablesFailed(db *gorm.DB, database string) bool {
	log.Info("init db tables with rollback")
	err := InitTables(db)
	if err != nil {
		DropDatabase(db, database)
		return false
	}
	return true
}

func InitTables(db *gorm.DB) error {
	log.Info("init db tables start")
	initSQL, err := ioutil.ReadFile(fmt.Sprintf("%s/init.sql", SQL_FILE_DIR))
	if err != nil {
		log.Errorf("read sql file failed: %v", err)
		return err
	}
	err = db.Exec(string(initSQL)).Error
	if err != nil {
		log.Errorf("init db tables failed: %v", err)
		return err
	}
	err = db.Exec(fmt.Sprintf("INSERT INTO db_version (version) VALUE ('%s')", migration.DB_VERSION_EXPECTED)).Error
	if err != nil {
		log.Errorf("init db version failed: %v", err)
		return err
	}
	log.Info("init db tables success")
	return err
}

func ExecuteIssus(db *gorm.DB, curVersion string) error {
	issus, err := ioutil.ReadDir(fmt.Sprintf("%s/issu", SQL_FILE_DIR))
	if err != nil {
		log.Errorf("read sql dir faild: %v", err)
		return err
	}
	nextVersions := getAscSortedNextVersions(issus, curVersion)
	log.Infof("issus to be executed: %v", nextVersions)
	for _, nv := range nextVersions {
		err = executeIssu(db, nv)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeIssu(db *gorm.DB, nextVersion string) error {
	issuSQL, err := ioutil.ReadFile(fmt.Sprintf("%s/issu/%s.sql", SQL_FILE_DIR, nextVersion))
	if err != nil {
		log.Errorf("read sql file (version: %s) failed: %v", nextVersion, err)
		return err
	}
	if len(issuSQL) == 0 {
		log.Infof("issu with no content (version: %s)", nextVersion)
		return nil
	}
	err = db.Exec(string(issuSQL)).Error
	if err != nil {
		log.Errorf("excute db issu (version: %s) failed: %v", nextVersion, err)
		return err
	}
	log.Infof("execute db issu (version: %s) success", nextVersion)
	return nil
}

func getAscSortedNextVersions(files []fs.FileInfo, curVersion string) []string {
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
