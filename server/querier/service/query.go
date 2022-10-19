/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/deepflowys/deepflow/server/querier/engine"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse"
	"github.com/deepflowys/deepflow/server/querier/prometheus"
	"github.com/prometheus/prometheus/prompb"
)

func Execute(args map[string]string) (result map[string][]interface{}, debug map[string]interface{}, err error) {
	db := getDbBy()
	var engine engine.Engine
	switch db {
	case "clickhouse":
		engine = &clickhouse.CHEngine{DB: args["db"], DataSource: args["datasource"]}
		engine.Init()
	}
	result, debug, err = engine.ExecuteQuery(args["sql"], args["query_uuid"])

	return result, debug, err
}

func getDbBy() string {
	return "clickhouse"
}

func PromReaderExecute(req *prompb.ReadRequest) (resp *prompb.ReadResponse, err error) {
	return prometheus.PromReaderExecute(req)
}
