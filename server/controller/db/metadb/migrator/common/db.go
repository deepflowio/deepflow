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

package common

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
)

type Edition struct {
	SchemeDir         string
	DBVersionTable    string
	DBVersionExpected string
}

func NewEdition(schemeDir string, dbVersionTable string, dbVersionExpected string) *Edition {
	return &Edition{
		SchemeDir:         schemeDir,
		DBVersionTable:    dbVersionTable,
		DBVersionExpected: dbVersionExpected,
	}
}

type DBConfig struct {
	DB     *gorm.DB
	Config config.MySqlConfig
}

func NewDBConfig(db *gorm.DB, cfg config.MySqlConfig) *DBConfig {
	return &DBConfig{
		DB:     db,
		Config: cfg,
	}
}

func (dc *DBConfig) GetDatabaseName() string {
	return dc.Config.Database
}

func (dc *DBConfig) SetDB(db *gorm.DB) {
	dc.DB = db
}

func (dc *DBConfig) SetConfig(c config.MySqlConfig) {
	dc.Config = c
}

func LogDBName(databaseName string, format string, a ...any) string {
	return fmt.Sprintf("[DB-%s] ", databaseName) + fmt.Sprintf(format, a...)
}

func GetSessionWithoutName(cfg config.MySqlConfig) (*gorm.DB, error) {
	connector, err := common.GetConnector(cfg, false, cfg.TimeOut, false)
	if err != nil {
		return nil, err
	}
	return common.InitSession(cfg, connector)
}

func GetSessionWithName(cfg config.MySqlConfig) (*gorm.DB, error) {
	// set multiStatements=true in dsn only when migrating MySQL
	connector, err := common.GetConnector(cfg, true, cfg.TimeOut*2, true)
	if err != nil {
		return nil, err
	}
	return common.InitSession(cfg, connector)
}
