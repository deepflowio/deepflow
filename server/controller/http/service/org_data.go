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

package service

import (
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	mysqlcfg "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"gorm.io/gorm"
)

// CreateORGData create database and backs up the controller and analyzer tables.
// Returns the database name and error.
func CreateORGData(dataCreate model.ORGDataCreate, mysqlCfg mysqlcfg.MySqlConfig) (string, error) {
	log.Infof("create org (id: %d) data", dataCreate.ORGID)
	defaultDatabase := mysqlCfg.Database
	cfg := common.ReplaceConfigDatabaseName(mysqlCfg, dataCreate.ORGID)
	existed, err := migrator.CreateDatabase(cfg) // TODO use orgID to create db
	if err != nil {
		return cfg.Database, err
	}
	if existed {
		return cfg.Database, errors.New(fmt.Sprintf("database (name: %s) already exists", cfg.Database))
	}

	var controllers []mysql.Controller
	var analyzers []mysql.Analyzer
	if err := mysql.DefaultDB.Unscoped().Find(&controllers).Error; err != nil {
		return defaultDatabase, err
	}
	if err := mysql.DefaultDB.Unscoped().Find(&analyzers).Error; err != nil {
		return defaultDatabase, err
	}

	db, err := mysql.GetDB(dataCreate.ORGID)
	if err != nil {
		return cfg.Database, err
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.CreateInBatches(controllers, len(controllers)).Error; err != nil {
			return err
		}
		return tx.CreateInBatches(analyzers, len(analyzers)).Error
	})
	return cfg.Database, nil
}

func DeleteORGData(orgID int, mysqlCfg mysqlcfg.MySqlConfig) (err error) {
	log.Infof("delete org (id: %d) data", orgID)
	cfg := common.ReplaceConfigDatabaseName(mysqlCfg, orgID)
	return migrator.DropDatabase(cfg)
}
