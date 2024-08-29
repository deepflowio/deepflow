/**
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
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlcommon "github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator/edition"
)

var log = logging.MustGetLogger("db.mysql.migrator")

// if configured database does not exist, it is considered a new deployment, will create database and init tables;
// if configured database exists, but db_version table does not exist, it is also considered a new deployment,
//
//	maybe we do not have permission to create database or other reasons, then will init all tables.
//
// if configured database exists, and db_version table exists, check whether db_version is the latest version
//
//	and upgrade based the result.
func Migrate(cfg config.MySqlConfig) error {
	if err := migrateDefaultDatabase(cfg); err != nil {
		return err
	}
	orgIDs, err := mysql.GetNonDefaultORGIDs()
	if err != nil {
		return err
	}
	for _, orgID := range orgIDs {
		if err = migrateNonDefaultDatabase(cfg, orgID); err != nil {
			return err
		}
	}
	return nil
}

func migrateDefaultDatabase(cfg config.MySqlConfig) error {
	copiedCfg := cfg
	databaseExisted, err := CreateDatabase(copiedCfg)
	if err != nil {
		return err
	}

	if err := mysql.InitDefaultDB(cfg); err != nil {
		return err
	}

	return upgradeDatabase(copiedCfg, databaseExisted)
}

func migrateNonDefaultDatabase(cfg config.MySqlConfig, orgID int) error {
	copiedCfg := mysqlcommon.ReplaceConfigDatabaseName(cfg, orgID)
	databaseExisted, err := CreateDatabase(copiedCfg)
	if err != nil {
		return err
	}

	return upgradeDatabase(copiedCfg, databaseExisted)
}

func upgradeDatabase(cfg config.MySqlConfig, run bool) error {
	if run {
		return edition.UpgradeDatabase(cfg)
	}
	return nil
}

func CreateDatabase(cfg config.MySqlConfig) (databaseExisted bool, err error) {
	db, err := common.GetSessionWithoutName(cfg)
	if err != nil {
		return
	}
	dc := common.NewDBConfig(db, cfg)
	databaseExisted, err = common.CreateDatabaseIfNotExists(dc)
	if err != nil {
		log.Error(common.LogDBName(cfg.Database, "database is not ready: %v", err))
		return
	}
	if !databaseExisted {
		db, err = common.GetSessionWithName(cfg)
		if err != nil {
			return
		}
		dc.SetDB(db)
		err = edition.DropDatabaseIfInitTablesFailed(dc)
	}
	return
}

func DropDatabase(cfg config.MySqlConfig) error {
	db, err := common.GetSessionWithoutName(cfg)
	if err != nil {
		return err
	}
	return common.DropDatabase(common.NewDBConfig(db, cfg))
}
