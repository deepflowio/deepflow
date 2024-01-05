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

package service

import (
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/engine"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
)

func Execute(args *common.QuerierParams) (jsonData map[string]interface{}, debug map[string]interface{}, err error) {
	db := getDbBy()
	var engine engine.Engine
	switch db {
	case "clickhouse":
		engine = &clickhouse.CHEngine{DB: args.DB, DataSource: args.DataSource, Context: args.Context}
		engine.Init()
	}
	result, debug, err := engine.ExecuteQuery(args)
	if result != nil {
		jsonData = result.ToJson()
	}
	return jsonData, debug, err
}

func getDbBy() string {
	return "clickhouse"
}
