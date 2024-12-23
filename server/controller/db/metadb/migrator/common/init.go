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
	"os"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/schema"
)

type EditionInitTablesFunc func(dc *DBConfig) error // TODO

func DropDatabaseIfInitTablesFailed(dc *DBConfig, editionFunc EditionInitTablesFunc) error {
	log.Info(LogDBName(dc.Config.Database, "drop database if fails to initialize tables"))
	err := editionFunc(dc)
	if err != nil {
		err := DropDatabase(dc)
		if err != nil {
			log.Error(LogDBName(dc.Config.Database, "failed to drop database: %s", err.Error()))
		}
		return err
	}
	return nil
}

func InitCETables(dc *DBConfig) error {
	err := InitTables(dc, schema.FILE_DIR)
	if err != nil {
		return err
	}
	return InsertDBVersion(dc, schema.DB_VERSION_TABLE, schema.DB_VERSION_EXPECTED)
}

func InitTables(dc *DBConfig, schemaDir string) error {
	log.Info(LogDBName(dc.Config.Database, "initialize %s tables", schemaDir)) // TODO

	// 先初始化所有组织需要的 CE 表，再判断数据库是否是 default 组织，如果是 default 组织，初始化仅 default 组织所需数据。
	err := InitORGTables(dc, schemaDir)
	if err != nil {
		return err
	}

	// 通过判断数据库名称后缀，判断数据库是否是 default 组织。
	if !strings.HasSuffix(dc.Config.Database, common.NON_DEFAULT_ORG_DATABASE_SUFFIX) {
		if err := InitDefaultORGTables(dc, schemaDir); err != nil {
			return err
		}
	}

	log.Info(LogDBName(dc.Config.Database, "initialized %s tables successfully", schemaDir))
	return nil
}

func InitORGTables(dc *DBConfig, schemaDir string) error {
	log.Info(LogDBName(dc.Config.Database, "initialize %s org tables", schemaDir))
	initSQL, err := os.ReadFile(fmt.Sprintf("%s/init.sql", schemaDir))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read %s org sql file: %s", schemaDir, err.Error()))
		return err
	}
	err = dc.DB.Exec(string(initSQL)).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to initialize %s org tables: %s", schemaDir, err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "initialized %s org tables successfully", schemaDir))
	return nil
}

func InitDefaultORGTables(dc *DBConfig, schemaDir string) error {
	log.Info(LogDBName(dc.Config.Database, "initialize %s default org tables", schemaDir))
	initSQL, err := os.ReadFile(fmt.Sprintf("%s/default_init.sql", schemaDir))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read %s default org sql file: %s", schemaDir, err.Error()))
		return err
	}
	err = dc.DB.Exec(string(initSQL)).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to initialize %s default org tables: %s", schemaDir, err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "initialized %s default org tables successfully", schemaDir))
	return nil
}
