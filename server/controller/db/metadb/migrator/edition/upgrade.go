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

package edition

import (
	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/schema"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/session"
)

func UpgradeDatabase(cfg config.Config) error {
	db, err := session.GetSessionWithName(cfg)
	if err != nil {
		return err
	}
	dc := common.NewDBConfig(db, cfg)

	return upgradeCE(dc, cfg)
}

func upgradeCE(dc *common.DBConfig, cfg config.Config) error {
	versionTableExists, err := common.CheckCEDBVersionTableExists(dc)
	if err != nil {
		return err
	}

	if !versionTableExists {
		return initTablesWithoutRollBack(dc) // TODO
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
	version, err := common.GetCEDBVersion(dc)
	if err != nil {
		log.Error(common.LogDBName(dc.Config.Database, "failed to get db version: %s", err.Error()))
		return err
	}

	log.Infof(common.LogDBName(dc.Config.Database, "current db version: %s, expected db version: %s", version, schema.DB_VERSION_EXPECTED))
	if version == "" {
		if dc.Config.DropDatabaseEnabled {
			return recreateDatabaseAndInitTables(dc)
		} else {
			log.Error(common.LogDBName(dc.Config.Database, "current db version is null, need manual handling"))
			return err
		}
	} else if version != schema.DB_VERSION_EXPECTED {
		return common.ExecuteCEIssues(dc, version)
	}
	return nil
}

func recreateDatabaseAndInitTables(dc *common.DBConfig) error {
	log.Info(common.LogDBName(dc.Config.Database, "recreate database and initialize tables"))
	common.DropDatabase(dc)
	db, err := session.GetSessionWithoutName(dc.Config)
	if err != nil {
		return err
	}
	err = common.CreateDatabase(common.NewDBConfig(db, dc.Config))
	if err != nil {
		log.Error(common.LogDBName(dc.Config.Database, "failed to create database: %s", err.Error()))
		return err
	}

	db, err = session.GetSessionWithName(dc.Config)
	if err != nil {
		return err
	}
	dc.SetDB(db)
	return DropDatabaseIfInitTablesFailed(dc)
}
