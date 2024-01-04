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

package clickhouse

import (
	"context"
	"github.com/deepflowio/deepflow/server/querier/common"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
)

func GetDatabases() *common.Result {
	var values []interface{}
	for db := range chCommon.DB_TABLE_MAP {
		values = append(values, []string{db})
	}
	return &common.Result{
		Columns: []interface{}{"name"},
		Values:  values,
	}
}

func GetTables(db string, ctx context.Context) *common.Result {
	var values []interface{}
	tables, ok := chCommon.DB_TABLE_MAP[db]
	if !ok {
		return nil
	}
	if db == "ext_metrics" || db == "deepflow_system" {
		values = append(values, chCommon.GetExtTables(db, ctx)...)
	} else if db == chCommon.DB_NAME_PROMETHEUS {
		values = append(values, chCommon.GetPrometheusTables(db, ctx)...)
	} else {
		for _, table := range tables {
			if table == "vtap_acl" {
				continue
			}
			datasource, err := chCommon.GetDatasources(db, table)
			if err != nil {
				log.Error(err)
			}
			values = append(values, []interface{}{table, datasource})
		}
	}
	return &common.Result{
		Columns: []interface{}{"name", "datasources"},
		Values:  values,
	}
}
