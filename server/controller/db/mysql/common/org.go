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

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
)

var log = logging.MustGetLogger("db.mysql.common")

// ORGIDToDatabaseName convert organization id to database name, format: 0002_deepflow
func ORGIDToDatabaseName(id int) string {
	return fmt.Sprintf(DATABASE_PREFIX_ALIGNMENT, id) + DATABASE_SUFFIX
}

func ReplaceConfigDatabaseName(cfg config.MySqlConfig, orgID int) config.MySqlConfig {
	copiedCfg := cfg
	copiedCfg.Database = ORGIDToDatabaseName(orgID)
	return copiedCfg
}
