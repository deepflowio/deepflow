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

package clickhouse

import (
	"fmt"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

type Table struct {
	Value string
}

func (t *Table) Format(m *view.Model) {
	m.AddTable(t.Value)
}

func GetVirtualTableFilter(db, table string) (view.Node, bool) {
	if db == "ext_metrics" {
		filter := fmt.Sprintf("virtual_table_name='%s'", table)
		return &view.Expr{Value: "(" + filter + ")"}, true
	}
	return nil, false
}
