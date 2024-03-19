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

package table

import (
	"errors"
	"fmt"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
)

var log = logging.MustGetLogger("db.mysql.migrator.table")

func UpgradeDatabase(cfg config.MySqlConfig) error {
	db, err := mysql.GetConnectionWithDatabase(cfg)
	if err != nil {
		return err
	}
	var dbVersionTable string
	err = db.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", cfg.Database, migration.DB_VERSION_TABLE)).Scan(&dbVersionTable).Error
	if err != nil {
		err = errors.New(fmt.Sprintf("check db_version table failed: %v", err))
		log.Error(err.Error())
		return err
	}
	if dbVersionTable == "" {
		return initTablesWithoutRollBack(db, cfg.Database)
	} else {
		return upgradeIfDBVersionNotLatest(db, cfg)
	}
}

func initTablesWithoutRollBack(db *gorm.DB, database string) error {
	log.Info("init db tables without rollback")
	return initTables(db)
}

func upgradeIfDBVersionNotLatest(db *gorm.DB, cfg config.MySqlConfig) error {
	log.Info("upgrade if db version is not the latest")
	var version string
	err := db.Raw(fmt.Sprintf("SELECT version FROM %s", migration.DB_VERSION_TABLE)).Scan(&version).Error
	if err != nil {
		err = errors.New(fmt.Sprintf("check db version failed: %v", err))
		log.Error(err.Error())
		return err
	}
	log.Infof("current db version: %s, expected db version: %s", version, migration.DB_VERSION_EXPECTED)
	if version == "" {
		if cfg.DropDatabaseEnabled {
			return recreateDatabaseAndInitTables(db, cfg)
		} else {
			err = errors.New("current db version is null, need manual handling")
			log.Error(err.Error())
			return err
		}
	} else if version != migration.DB_VERSION_EXPECTED {
		return common.ExecuteIssus(db, version)
	}
	return nil
}

func recreateDatabaseAndInitTables(db *gorm.DB, cfg config.MySqlConfig) error {
	log.Info("recreate database and init tables")
	common.DropDatabase(db, cfg.Database)
	db, err := mysql.GetConnectionWithoutDatabase(cfg)
	if err != nil {
		return err
	}
	err = common.CreateDatabase(db, cfg.Database)
	if err != nil {
		err = errors.New(fmt.Sprintf("created database %s failed: %v", cfg.Database, err))
		log.Error(err.Error())
		return err
	}

	db, err = mysql.GetConnectionWithDatabase(cfg)
	if err != nil {
		return err
	}
	return DropDatabaseIfInitTablesFailed(db, cfg.Database)
}


func DropDatabaseIfInitTablesFailed(db *gorm.DB, database string) error {
	log.Info("drop database if init tables failed")
	err := initTables(db)
	if err != nil {
		err := common.DropDatabase(db, database)
		if err != nil {
			err = errors.New(fmt.Sprintf("drop database %s failed: %v", database, err))
			log.Error(err.Error())
		}
		return err
	}
	return nil
}

func initTables(db *gorm.DB) error {
	log.Info("init db tables start")
	if err := common.InitEETables(db); err != nil {
		return err
	}
	if err := common.InitDBVersion(db); err != nil {
		return err
	}
	log.Info("init db tables success")
	return nil
}
