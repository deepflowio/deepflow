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

package session

import (
	"fmt"
	l "log"
	"os"
	"time"

	"github.com/op/go-logging"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/session/edition"
)

var log = logging.MustGetLogger("db.metadb.session")

func GetSessionWithoutName(cfg config.Config) (*gorm.DB, error) {
	return initSession(
		config.SessionConfig{
			DBCfg:              cfg,
			TimeoutCoefficient: 1,
		},
	)
}

func GetSessionWithName(cfg config.Config) (*gorm.DB, error) {
	return initSession(
		config.SessionConfig{
			DBCfg:              cfg,
			UseDabase:          true,
			TimeoutCoefficient: 2,
			MultiStatements:    true,
		},
	)
}

func GetSession(cfg config.Config) (*gorm.DB, error) {
	return initSession(
		config.SessionConfig{
			DBCfg:              cfg,
			UseDabase:          true,
			TimeoutCoefficient: 1,
		})
}

func initSession(cfg config.SessionConfig) (*gorm.DB, error) {
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

func getDialector(cfg config.SessionConfig) (gorm.Dialector, error) {
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
	default:
		return edition.GetDialector(cfg)
	}
}
