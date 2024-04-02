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
	"fmt"

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator/common"
)

var log = logging.MustGetLogger("db.mysql.migrator.table")

func UpgradeDatabase(cfg config.MySqlConfig) error {
	db, err := common.GetSessionWithName(cfg)
	if err != nil {
		return err
	}

	dc := common.NewDBConfig(db, cfg)
	var dbVersionTable string
	err = db.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", cfg.Database, migration.DB_VERSION_TABLE)).Scan(&dbVersionTable).Error
	if err != nil {
		log.Error(common.LogDBName(dc.Config.Database, "failed to check db_version table: %s", err.Error()))
		return err
	}
	if dbVersionTable == "" {
		return initTablesWithoutRollBack(dc)
	} else {
		return upgradeIfDBVersionNotLatest(dc)
	}
}

func initTablesWithoutRollBack(dc *common.DBConfig) error {
	log.Info(common.LogDBName(dc.Config.Database, "initialize db tables without rollback"))
	return initTables(dc)
}

func upgradeIfDBVersionNotLatest(dc *common.DBConfig) error {
	log.Info(common.LogDBName(dc.Config.Database, "upgrade if db version is not the latest"))
	var version string
	err := dc.DB.Raw(fmt.Sprintf("SELECT version FROM %s", migration.DB_VERSION_TABLE)).Scan(&version).Error
	if err != nil {
		log.Error(common.LogDBName(dc.Config.Database, "failed to check db version: %s", err.Error()))
		return err
	}
	log.Infof(common.LogDBName(dc.Config.Database, "current db version: %s, expected db version: %s", version, migration.DB_VERSION_EXPECTED))
	if version == "" {
		if dc.Config.DropDatabaseEnabled {
			return recreateDatabaseAndInitTables(dc)
		} else {
			log.Error(common.LogDBName(dc.Config.Database, "current db version is null, need manual handling"))
			return err
		}
	} else if version != migration.DB_VERSION_EXPECTED {
		return common.ExecuteIssues(dc, version)
	}
	return nil
}

func recreateDatabaseAndInitTables(dc *common.DBConfig) error {
	log.Info(common.LogDBName(dc.Config.Database, "recreate database and initialize tables"))
	common.DropDatabase(dc)
	db, err := common.GetSessionWithoutName(dc.Config)
	if err != nil {
		return err
	}
	err = common.CreateDatabase(common.NewDBConfig(db, dc.Config))
	if err != nil {
		log.Error(common.LogDBName(dc.Config.Database, "failed to create database: %s", err.Error()))
		return err
	}

	db, err = common.GetSessionWithName(dc.Config)
	if err != nil {
		return err
	}
	dc.SetDB(db)
	return DropDatabaseIfInitTablesFailed(dc)
}

func DropDatabaseIfInitTablesFailed(dc *common.DBConfig) error {
	log.Info(common.LogDBName(dc.Config.Database, "drop database if fails to initialize tables"))
	err := initTables(dc)
	if err != nil {
		err := common.DropDatabase(dc)
		if err != nil {
			log.Error(common.LogDBName(dc.Config.Database, "failed to drop database: %s", err.Error()))
		}
		return err
	}
	return nil
}

func initTables(dc *common.DBConfig) error {
	log.Info(common.LogDBName(dc.Config.Database, "initialize db tables"))
	if err := common.InitCETables(dc); err != nil {
		return err
	}
	if err := common.InitDBVersion(dc); err != nil {
		return err
	}
	log.Info(common.LogDBName(dc.Config.Database, "initialized db tables successfully"))
	return nil
}
