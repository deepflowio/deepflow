/*
 * Copyright (c) 2023 Yunshan Networks
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

package engine

import (
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/xwb1989/sqlparser"
)

type Engine interface {
	TransSelect(sqlparser.SelectExprs) error
	TransFrom(sqlparser.TableExprs) error
	TransGroupBy(sqlparser.GroupBy) error
	TransDerivativeGroupBy(sqlparser.GroupBy) error
	TransWhere(*sqlparser.Where) error
	TransHaving(*sqlparser.Where) error
	TransOrderBy(sqlparser.OrderBy) error
	TransLimit(*sqlparser.Limit) error
	ToSQLString() string
	Init()
	ExecuteQuery(*common.QuerierParams) (*common.Result, map[string]interface{}, error)
}
