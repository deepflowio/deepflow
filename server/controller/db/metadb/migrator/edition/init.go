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
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/common"
)

var log = logging.MustGetLogger("db.metadb.migrator.edition")

func DropDatabaseIfInitTablesFailed(dc *common.DBConfig) error {
	log.Infof(common.LogDBName(dc.Config.Database, "drop database if init CE tables failed"))
	return common.DropDatabaseIfInitTablesFailed(dc, initTables)
}

func initTables(dc *common.DBConfig) error {
	log.Info(common.LogDBName(dc.Config.Database, "initialize db tables"))
	if err := common.InitCETables(dc); err != nil {
		return err
	}
	log.Info(common.LogDBName(dc.Config.Database, "initialized db tables successfully"))
	return nil
}
