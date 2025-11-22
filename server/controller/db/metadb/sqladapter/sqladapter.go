/**
 * Copyright (c) 2025 Yunshan Networks
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

package sqladapter

import (
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/sqladapter/edition"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/sqladapter/types"
)

var log = logging.MustGetLogger("db.metadb.migrator.schema")

func GetSQLAdapter(cfg config.Config) types.SQLAdapter { // TODO merge into session
	var r types.SQLAdapter
	switch cfg.Type {
	case config.MetaDBTypeMySQL:
		r = &MySQLAdapter{}
	case config.MetaDBTypePostgreSQL:
		r = &PostgreSQLAdapter{}
	default:
		var err error
		r, err = edition.GetAdapter(cfg)
		if err != nil {
			log.Fatalf("get sql adapter failed: %v", err)
		}
	}
	r.SetConfig(cfg)
	return r
}
