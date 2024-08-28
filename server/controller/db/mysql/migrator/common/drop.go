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
)

func DropDatabase(dc *DBConfig) error {
	log.Infof(LogDBName(dc.Config.Database, "drop database"))
	var databaseName string
	dc.DB.Raw(fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='%s'", dc.Config.Database)).Scan(&databaseName)
	if databaseName == dc.Config.Database {
		return dc.DB.Exec(fmt.Sprintf("DROP DATABASE %s", dc.Config.Database)).Error
	} else {
		log.Infof(LogDBName(dc.Config.Database, "database doesn't exist"))
		return nil
	}
}
