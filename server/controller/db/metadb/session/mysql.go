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
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"time"

	mysql_driver "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
)

func getMySQLConnector(cfg config.SessionConfig) (driver.Connector, error) {
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
