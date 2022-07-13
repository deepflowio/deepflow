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

package mysql

import (
	"fmt"
	"time"

	"github.com/op/go-logging"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var log = logging.MustGetLogger("db.mysql")
var Db *gorm.DB

type MySqlConfig struct {
	Database     string `default:"deepflow" yaml:"database"`
	Host         string `default:"mysql" yaml:"host"`
	Port         uint32 `default:"30130" yaml:"port"`
	UserName     string `default:"root" yaml:"user-name"`
	UserPassword string `default:"metaflow" yaml:"user-password"`
	TimeOut      uint32 `default:"30" yaml:"timeout"`
}

func Gorm(cfg MySqlConfig) *gorm.DB {
	dsn := getDSN(cfg, cfg.Database, cfg.TimeOut, false)
	return getGormDB(dsn)
}

func getDSN(cfg MySqlConfig, database string, timeout uint32, multiStatements bool) string {
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

func getGormDB(dsn string) *gorm.DB {
	Db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                       dsn,   // DSN data source name
		DefaultStringSize:         256,   // string 类型字段的默认长度
		DisableDatetimePrecision:  true,  // 禁用 datetime 精度，MySQL 5.6 之前的数据库不支持
		DontSupportRenameIndex:    true,  // 重命名索引时采用删除并新建的方式，MySQL 5.7 之前的数据库和 MariaDB 不支持重命名索引
		DontSupportRenameColumn:   true,  // 用 `change` 重命名列，MySQL 8 之前的数据库和 MariaDB 不支持重命名列
		SkipInitializeWithVersion: false, // 根据当前 MySQL 版本自动配置
	}), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true}, // 设置全局表名禁用复数
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
