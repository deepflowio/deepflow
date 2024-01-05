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

package migrator

import (
	"fmt"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	. "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
)

var log = logging.MustGetLogger("db.migrator.mysql")

// if configured database does not exist, it is considered a new deployment, will create database and init tables;
// if configured database exists, but db_version table does not exist, it is also considered a new deployment,
//
//	maybe we do not have permission to create database or other reasons, then will init all tables.
//
// if configured database exists, and db_version table exists, check whether db_version is the latest version
//
//	and upgrade based the result.
func MigrateMySQL(cfg MySqlConfig) bool {
	db := mysql.GetConnectionWithoutDatabase(cfg)
	if db == nil {
		return false
	}
	databaseExisted, err := CreateDatabaseIfNotExists(db, cfg.Database)
	if err != nil {
		log.Errorf("database: %s is not ready: %v", cfg.Database, err)
		return false
	}

	db = mysql.GetConnectionWithDatabase(cfg)
	if db == nil {
		return false
	}
	if !databaseExisted {
		return DropDatabaseIfInitTablesFailed(db, cfg.Database)
	} else {
		var dbVersionTable string
		err = db.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", cfg.Database, migration.DB_VERSION_TABLE)).Scan(&dbVersionTable).Error
		if err != nil {
			log.Errorf("check db_version table failed: %v", err)
			return false
		}
		if dbVersionTable == "" {
			return InitTablesWithoutRollBack(db, cfg.Database)
		} else {
			return UpgradeIfDBVersionNotLatest(db, cfg)
		}
	}
}

func InitTablesWithoutRollBack(db *gorm.DB, database string) bool {
	log.Info("init db tables without rollback")
	err := InitTables(db)
	if err != nil {
		return false
	}
	return true
}

func UpgradeIfDBVersionNotLatest(db *gorm.DB, cfg MySqlConfig) bool {
	log.Info("upgrade if db version is not the latest")
	var version string
	err := db.Raw(fmt.Sprintf("SELECT version FROM %s", migration.DB_VERSION_TABLE)).Scan(&version).Error
	if err != nil {
		log.Errorf("check db version failed: %v", err)
		return false
	}
	log.Infof("current db version: %s, expected db version: %s", version, migration.DB_VERSION_EXPECTED)
	if version == "" {
		if cfg.DropDatabaseEnabled {
			return RecreateDatabaseAndInitTables(db, cfg)
		} else {
			log.Errorf("current db version is null, need manual handling")
			return false
		}
	} else if version != migration.DB_VERSION_EXPECTED {
		err = ExecuteIssus(db, version)
		if err != nil {
			return false
		}
		return true
	}
	return true
}

func RecreateDatabaseAndInitTables(db *gorm.DB, cfg MySqlConfig) bool {
	log.Info("recreate database and init tables")
	DropDatabase(db, cfg.Database)
	db = mysql.GetConnectionWithoutDatabase(cfg)
	if db == nil {
		return false
	}
	err := CreateDatabase(db, cfg.Database)
	if err != nil {
		log.Errorf("created database %s failed: %v", cfg.Database, err)
		return false
	}

	db = mysql.GetConnectionWithDatabase(cfg)
	if db == nil {
		return false
	}
	return DropDatabaseIfInitTablesFailed(db, cfg.Database)
}
