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

package migrator

import (
	"fmt"

	"github.com/op/go-logging"

	. "github.com/deepflowys/deepflow/server/controller/db/mysql/common"
	. "github.com/deepflowys/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowys/deepflow/server/controller/db/mysql/migration"
)

var log = logging.MustGetLogger("db.migrator.mysql")

// if database or version info not exist, create database and tables;
// if database exsits, execute issue if db version not equal lastest version
func MigrateMySQL(cfg MySqlConfig) bool {
	db := GetConnectionWithoudDatabase(cfg)
	if db == nil {
		return false
	}
	existed, err := CreateDatabaseIfNotExists(db, cfg.Database)
	if err != nil {
		log.Errorf("database: %s is not ready: %v", cfg.Database, err)
		return false
	}

	db = GetConnectionWithDatabase(cfg)
	if db == nil {
		return false
	}
	if !existed {
		return RollbackIfInitTablesFailed(db, cfg.Database)
	} else {
		var version string
		err = db.Raw(fmt.Sprintf("SELECT version FROM db_version")).Scan(&version).Error
		if err != nil {
			log.Errorf("check db version failed: %v", err)
			return false
		}
		log.Infof("current db version: %s, expected db version: %s", version, migration.DB_VERSION_EXPECTED)
		if version == "" {
			// TODO drop database is a dangerous operation
			DropDatabase(db, cfg.Database)
			db = GetConnectionWithoudDatabase(cfg)
			if db == nil {
				return false
			}
			err = CreateDatabase(db, cfg.Database)
			if err != nil {
				log.Errorf("created database %s failed: %v", cfg.Database, err)
				return false
			}

			db = GetConnectionWithDatabase(cfg)
			if db == nil {
				return false
			}
			return RollbackIfInitTablesFailed(db, cfg.Database)
		} else if version != migration.DB_VERSION_EXPECTED {
			err = ExecuteIssus(db, version)
			if err != nil {
				return false
			}
		}
	}
	return true
}
