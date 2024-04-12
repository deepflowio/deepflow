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

package mysql

import (
	"errors"
	"fmt"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
)

var log = logging.MustGetLogger("db.mysql")
var Db *gorm.DB

func InitMySQL(cfg config.MySqlConfig) error {
	Db, _ = common.GetSession(cfg)
	if Db == nil {
		return errors.New("connect mysql failed")
	}
	var version string
	err := Db.Raw(fmt.Sprintf("SELECT version FROM db_version")).Scan(&version).Error
	if err != nil {
		return errors.New("get current db version failed")
	}
	if version != migration.DB_VERSION_EXPECTED {
		return errors.New(fmt.Sprintf("current db version: %s != expected db version: %s", version, migration.DB_VERSION_EXPECTED))
	}
	return nil
}
