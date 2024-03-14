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
	"errors"
	"fmt"

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator/table"
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
func MigrateMySQL(cfg config.MySqlConfig) error {
	if databaseExisted, err := CreateDatabase(cfg); err != nil {
		return err
	} else if databaseExisted {
		return table.UpgradeDatabase(cfg)
	}
	return nil
}

func CreateDatabase(cfg config.MySqlConfig) (databaseExisted bool, err error) {
	db, err := mysql.GetConnectionWithoutDatabase(cfg)
	if err != nil {
		return
	}
	databaseExisted, err = common.CreateDatabaseIfNotExists(db, cfg.Database)
	if err != nil {
		err = errors.New(fmt.Sprintf("database: %s is not ready: %v", cfg.Database, err))
		log.Error(err.Error())
		return
	}
	if !databaseExisted {
		db, err = mysql.GetConnectionWithDatabase(cfg)
		if err != nil {
			return
		}
		if err = table.DropDatabaseIfInitTablesFailed(db, cfg.Database); err != nil {
			return
		}
	}
	mysql.DBMap.Add(cfg.Database, db)
	return
}

func DropDatabase(cfg config.MySqlConfig) error {
	db, err := mysql.GetConnectionWithDatabase(cfg)
	if err != nil {
		return err
	}
	return common.DropDatabase(db, cfg.Database)
}
