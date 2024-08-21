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
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
)

func SimpleExecute(args *common.QuerierParams) (result *common.Result, debug map[string]interface{}, err error) {
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       "default",
		Context:  args.Context,
	}
	query_uuid := args.QueryUUID
	debugInfo := &client.DebugInfo{}
	queryDebug := &client.Debug{
		IP:        config.Cfg.Clickhouse.Host,
		QueryUUID: query_uuid,
	}
	chClient.Debug = queryDebug
	result, err = chClient.DoQuery(&client.QueryParams{Sql: args.Sql, UseQueryCache: args.UseQueryCache, QueryCacheTTL: args.QueryCacheTTL})
	debugInfo.Debug = append(debugInfo.Debug, *queryDebug)
	debug = debugInfo.Get()
	return
}
