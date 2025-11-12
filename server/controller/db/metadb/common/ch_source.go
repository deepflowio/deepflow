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

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
)

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
