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
	"net"
	"os"
	"time"

	mysql_driver "github.com/go-sql-driver/mysql"
	dameng_driver "github.com/godoes/gorm-dameng"
	postgres_driver "github.com/lib/pq"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
)

type SessionConfig struct {
	DBCfg config.Config
	// set UseDabase=false in dsn only when migrating Metadb
	UseDabase bool
	// set TimeoutCoefficient=2 in dsn only when migrating Metadb
	TimeoutCoefficient uint16
	// set multiStatements=true in dsn only when migrating Metadb
	MultiStatements bool
}

func GetSession(cfg config.Config) (*gorm.DB, error) {
	return InitSession(SessionConfig{
		DBCfg:              cfg,
		UseDabase:          true,
		TimeoutCoefficient: 1,
	})
}

func InitSession(cfg SessionConfig) (*gorm.DB, error) {
	dialector, err := getDialector(cfg)
	if dialector == nil {
		return nil, fmt.Errorf("failed to get dialector for database type: %s, err: %s", cfg.DBCfg.Type, err.Error())
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
	log.Infof("%s, initialized mysql session successfully", cfg.DBCfg.Database)

	sqlDB, _ := db.DB()
	// 限制最大空闲连接数、最大连接数和连接的生命周期
	sqlDB.SetMaxIdleConns(int(cfg.DBCfg.MaxIdleConns))
	sqlDB.SetMaxOpenConns(int(cfg.DBCfg.MaxOpenConns))
	sqlDB.SetConnMaxLifetime(time.Duration(int(cfg.DBCfg.ConnMaxLifeTime) * int(time.Minute)))
	log.Infof("%s, db stats: %#v", cfg.DBCfg.Database, sqlDB.Stats())
	return db, nil
}

func getDialector(cfg SessionConfig) (gorm.Dialector, error) {
	switch cfg.DBCfg.Type {
	case config.MetaDBTypeMySQL:
		conn, err := getMySQLConnector(cfg)
		if err != nil {
			return nil, err
		}
		return getMySQLDialector(conn), nil
	case config.MetaDBTypePostgreSQL:
		conn, err := getPostgreSQLConnector(cfg)
		if err != nil {
			return nil, err
		}
		return getPostgresDialector(conn), nil
	case config.MetaDBTypeDM:
		return getDaMengDialector(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.DBCfg.Type)
	}
}

func getMySQLConnector(cfg SessionConfig) (driver.Connector, error) {
	var database string
	if cfg.UseDabase {
		database = cfg.DBCfg.Database
	}

	location, err := time.LoadLocation("Local")
	if err != nil {
		log.Error("Get location failed with error: %v", err.Error())
		return nil, err
	}

	config := mysql_driver.NewConfig()
	config.User = cfg.DBCfg.UserName
	config.Passwd = cfg.DBCfg.UserPassword
	config.Net = "tcp"
	config.Addr = net.JoinHostPort(cfg.DBCfg.Host, fmt.Sprintf("%d", cfg.DBCfg.Port))
	config.DBName = database
	config.AllowNativePasswords = true
	config.Loc = location
	config.Timeout = time.Duration(cfg.TimeoutCoefficient*cfg.DBCfg.TimeOut) * time.Second
	config.ParseTime = true
	config.MultiStatements = cfg.MultiStatements
	config.Params = map[string]string{"charset": "utf8mb4"}

	connector, err := mysql_driver.NewConnector(config)
	if err != nil {
		log.Error("get database(%s) connector failed with error: %v", database, err.Error())
		return nil, err
	}
	return connector, nil
}

func getPostgreSQLConnector(cfg SessionConfig) (driver.Connector, error) {
	connStr := "user=" + cfg.DBCfg.UserName +
		" password=" + cfg.DBCfg.UserPassword +
		" host=" + cfg.DBCfg.Host +
		" port=" + fmt.Sprintf("%d", cfg.DBCfg.Port) +
		" connect_timeout=" + fmt.Sprintf("%d", cfg.TimeoutCoefficient*cfg.DBCfg.TimeOut) +
		" sslmode=disable" +
		" client_encoding=UTF8"

	database := "postgres" // TODO
	if cfg.UseDabase {
		database = cfg.DBCfg.Database
	}
	connStr += " dbname=" + database +
		" search_path=" + cfg.DBCfg.Schema

	connector, err := postgres_driver.NewConnector(connStr)
	if err != nil {
		log.Error("get database(%s) connector failed with error: %v", database, err.Error())
		return nil, err
	}
	return connector, nil
}

func getMySQLDialector(conn driver.Connector) gorm.Dialector {
	return mysql.New(mysql.Config{
		Conn:                      sql.OpenDB(conn),
		DefaultStringSize:         256,   // string 类型字段的默认长度
		DisableDatetimePrecision:  true,  // 禁用 datetime 精度，MySQL 5.6 之前的数据库不支持
		DontSupportRenameIndex:    true,  // 重命名索引时采用删除并新建的方式，MySQL 5.7 之前的数据库和 MariaDB 不支持重命名索引
		DontSupportRenameColumn:   true,  // 用 `change` 重命名列，MySQL 8 之前的数据库和 MariaDB 不支持重命名列
		SkipInitializeWithVersion: false, // 根据当前 MySQL 版本自动配置
	})
}

func getPostgresDialector(conn driver.Connector) gorm.Dialector {
	return postgres.New(postgres.Config{
		Conn: sql.OpenDB(conn),
	})
}

func getDaMengDialector(cfg SessionConfig) gorm.Dialector {
	// options := map[string]string{
	// 	"appName":        "GORM deepflow",
	// 	"connectTimeout": fmt.Sprintf("%d", cfg.TimeoutCoefficient*cfg.DBCfg.TimeOut),
	// } TODO
	dsn := fmt.Sprintf("dm://%s:%s@%s:%d", cfg.DBCfg.UserName, cfg.DBCfg.UserPassword, cfg.DBCfg.Host, cfg.DBCfg.Port)
	if cfg.UseDabase {
		// options["schema"] = cfg.DBCfg.Database
		dsn = dsn + fmt.Sprintf("?schema=%s", cfg.DBCfg.Database)
	}
	// dsn := dameng_driver.BuildUrl(cfg.DBCfg.UserName, cfg.DBCfg.UserPassword, cfg.DBCfg.Host, int(cfg.DBCfg.Port), options)
	return dameng_driver.New(dameng_driver.Config{DSN: dsn})
}

type ClickHouseSource struct {
	Name         string
	Database     string
	Host         string
	Port         uint32
	ProxyHost    string
	ProxyPort    uint32
	UserName     string
	UserPassword string
	ReplicaSQL   string
	DSN          string // DM
}

func GetClickhouseSource(cfg config.Config) ClickHouseSource {
	source := ClickHouseSource{}
	switch cfg.Type {
	case config.MetaDBTypeMySQL:
		source.Name = SOURCE_MYSQL
		source.Database = cfg.Database
		source.Host = ""
		source.UserName = cfg.UserName
		source.UserPassword = cfg.UserPassword
		if cfg.ProxyHost != "" {
			source.ReplicaSQL = fmt.Sprintf(SQL_REPLICA, cfg.ProxyHost) + " "
			source.Port = cfg.ProxyPort
		} else {
			source.ReplicaSQL = fmt.Sprintf(SQL_REPLICA, cfg.Host) + " "
			source.Port = cfg.Port
		}
	case config.MetaDBTypePostgreSQL:
		source.Name = SOURCE_POSTGRESQL
		source.Database = cfg.Database
		source.ReplicaSQL = ""
		source.UserName = cfg.UserName
		source.UserPassword = cfg.UserPassword
		if cfg.ProxyHost != "" {
			source.Host = "HOST '" + cfg.ProxyHost + "' "
			source.Port = cfg.ProxyPort
		} else {
			source.Host = "HOST '" + cfg.Host + "' "
			source.Port = cfg.Port
		}
	case config.MetaDBTypeDM:
		source.Name = SOURCE_DM
		source.DSN = cfg.DSN
		source.Database = cfg.Database
	}
	return source
}
