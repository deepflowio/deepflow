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
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	mysqlcfg "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator"
	"github.com/deepflowio/deepflow/server/controller/http/model"
)

func CreateDatabase(dataCreate model.DatabaseCreate, mysqlCfg mysqlcfg.MySqlConfig) (database string, err error) {
	log.Infof("create organization (id: %s) databases", dataCreate.OrganizationID)
	database = common.OrganizationIDToDatabaseName(dataCreate.OrganizationID)
	cfg := mysqlCfg
	cfg.Database = database
	existed, err := migrator.CreateDatabase(cfg)
	if existed {
		err = errors.New(fmt.Sprintf("database (name: %s) already exists", database))
	}
	return
}

func DeleteDatabase(organizationID string, mysqlCfg mysqlcfg.MySqlConfig) (err error) {
	log.Infof("delete organization (id: %s) databases", organizationID)
	id, _ := strconv.Atoi(organizationID)
	cfg := mysqlCfg
	cfg.Database = common.OrganizationIDToDatabaseName(id)
	return migrator.DropDatabase(cfg)
}
