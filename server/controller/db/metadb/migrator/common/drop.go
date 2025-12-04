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
	"github.com/deepflowio/deepflow/server/controller/db/metadb/session"
)

func DropDatabase(dc *DBConfig) error {
	db, err := session.GetSessionWithoutName(dc.Config)
	if err != nil {
		return err
	}
	dc.SetDB(db)

	log.Infof(LogDBName(dc.Config.Database, "drop database"))
	var databaseName string
	dc.DB.Raw(dc.SqlFmt.SelectDatabase()).Scan(&databaseName)
	if databaseName == dc.Config.Database {
		return dc.DB.Exec(dc.SqlFmt.DropDatabase()).Error
	} else {
		log.Infof(LogDBName(dc.Config.Database, "database doesn't exist"))
		return nil
	}
}
