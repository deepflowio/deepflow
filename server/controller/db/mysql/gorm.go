/*
 * Copyright (c) 2023 Yunshan Networks
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
	"errors"
	"fmt"
	l "log"
	"os"
	"time"

	"github.com/op/go-logging"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	. "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
)

var log = logging.MustGetLogger("db.mysql")
var Db *gorm.DB
var DbConfig MySqlConfig

func InitMySQL(cfg MySqlConfig) error {
	DbConfig = cfg
	Db = Gorm(cfg)
	if Db == nil {
		return errors.New("connect mysql failed")
	}
	var version string
	err := Db.Raw(fmt.Sprintf("SELECT version FROM db_version")).Scan(&version).Error
	if err != nil {
		return errors.New("get current db version failed")
	}
	if version != migration.DB_VERSION_EXPECTED {
		return errors.New(fmt.Sprintf("current db version: %s != expected db version: %s", version, migration.DB_VERSION_EXPECTED))
	}
	return nil
}

func Gorm(cfg MySqlConfig) *gorm.DB {
	dsn := GetDSN(cfg, cfg.Database, cfg.TimeOut, false)
	return GetGormDB(dsn)
}

func GetResultSetMax() int {
	return int(DbConfig.ResultSetMax)
}

func GetConnectionWithoutDatabase(cfg MySqlConfig) *gorm.DB {
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
