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
	"database/sql"
	"database/sql/driver"
	"fmt"
	l "log"
	"os"
	"time"

	mysql_driver "github.com/go-sql-driver/mysql"
	postgres_driver "github.com/lib/pq"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
)

func GetSession(cfg config.Config) (*gorm.DB, error) {
	connector, err := GetConnector(cfg, true, cfg.TimeOut, false)
	if err != nil {
		return nil, err
	}
	return InitSession(cfg, connector)
}

func GetConnector(cfg config.Config, useDatabase bool, timeout uint32, multiStatements bool) (driver.Connector, error) {
	switch cfg.Type {
	case config.MetaDBTypeMySQL:
		return getMySQLConnector(cfg, useDatabase, timeout, multiStatements)
	case config.MetaDBTypePostgreSQL:
		return getPostgreSQLConnector(cfg, useDatabase, timeout, multiStatements)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Type)
	}
}

func getMySQLConnector(cfg config.Config, useDatabase bool, timeout uint32, multiStatements bool) (driver.Connector, error) {
	var database string
	if useDatabase {
		database = cfg.Database
	}

	location, err := time.LoadLocation("Local")
	if err != nil {
		log.Error("Get location failed with error: %v", err.Error())
		return nil, err
	}

	config := mysql_driver.NewConfig()
	config.User = cfg.UserName
	config.Passwd = cfg.UserPassword
	config.Net = "tcp"
	config.Addr = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	config.DBName = database
	config.AllowNativePasswords = true
	config.Loc = location
	config.Timeout = time.Duration(timeout) * time.Second
	config.ParseTime = true
	config.MultiStatements = multiStatements
	config.Params = map[string]string{"charset": "utf8mb4"}

	connector, err := mysql_driver.NewConnector(config)
	if err != nil {
		log.Error("get database(%s) connector failed with error: %v", database, err.Error())
		return nil, err
	}
	return connector, nil
}

func getPostgreSQLConnector(cfg config.Config, useDatabase bool, timeout uint32, multiStatements bool) (driver.Connector, error) {
	var database string
	var schema string
	if useDatabase {
		database = cfg.Database
		schema = cfg.Schema
	}

	connStr := "user=" + cfg.UserName +
		" password=" + cfg.UserPassword +
		" host=" + cfg.Host +
		" port=" + fmt.Sprintf("%d", cfg.Port) +
		" dbname=" + database +
		" search_path=" + schema +
		" connect_timeout=" + fmt.Sprintf("%d", int(timeout)) +
		" sslmode=disable" +
		" client_encoding=UTF8"

	connector, err := postgres_driver.NewConnector(connStr)
	if err != nil {
		log.Error("get database(%s) connector failed with error: %v", database, err.Error())
		return nil, err
	}
	return connector, nil
}

func InitSession(cfg config.Config, connector driver.Connector) (*gorm.DB, error) {
	dialector := getDialector(cfg, connector)
	if dialector == nil {
		return nil, fmt.Errorf("failed to get dialector for database type: %s", cfg.Type)
	}
	db, err := gorm.Open(
		dialector,
		&gorm.Config{
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
		log.Errorf("failed to initialize session: %v", err.Error())
		return nil, err
	}
	log.Infof("%s, initialized mysql session successfully", cfg.Database)

	sqlDB, _ := db.DB()
	// 限制最大空闲连接数、最大连接数和连接的生命周期
	sqlDB.SetMaxIdleConns(int(cfg.MaxIdleConns))
	sqlDB.SetMaxOpenConns(int(cfg.MaxOpenConns))
	sqlDB.SetConnMaxLifetime(time.Duration(int(cfg.ConnMaxLifeTime) * int(time.Minute)))
	log.Infof("%s, db stats: %#v", cfg.Database, sqlDB.Stats())
	return db, nil
}

func getDialector(cfg config.Config, connector driver.Connector) gorm.Dialector {
	switch cfg.Type {
	case config.MetaDBTypeMySQL:
		return getMySQLDialector(cfg, connector)
	case config.MetaDBTypePostgreSQL:
		return getPostgresDialector(cfg, connector)
	default:
		log.Errorf("unsupported database type: %s", cfg.Type)
		return nil
	}
}

func getMySQLDialector(cfg config.Config, conn driver.Connector) gorm.Dialector {
	return mysql.New(mysql.Config{
		Conn:                      sql.OpenDB(conn),
		DefaultStringSize:         256,   // string 类型字段的默认长度
		DisableDatetimePrecision:  true,  // 禁用 datetime 精度，MySQL 5.6 之前的数据库不支持
		DontSupportRenameIndex:    true,  // 重命名索引时采用删除并新建的方式，MySQL 5.7 之前的数据库和 MariaDB 不支持重命名索引
		DontSupportRenameColumn:   true,  // 用 `change` 重命名列，MySQL 8 之前的数据库和 MariaDB 不支持重命名列
		SkipInitializeWithVersion: false, // 根据当前 MySQL 版本自动配置
	})
}

func getPostgresDialector(cfg config.Config, conn driver.Connector) gorm.Dialector {
	return postgres.New(postgres.Config{
		Conn: sql.OpenDB(conn),
	})
}
