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
	"fmt"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/trans_prometheus"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

type Table struct {
	Value string
}

func (t *Table) Format(m *view.Model) {
	m.AddTable(t.Value)
}

func GetVirtualTableFilter(db, table string) (view.Node, bool) {
	if db == "ext_metrics" || db == "deepflow_system" {
		filter := fmt.Sprintf("virtual_table_name='%s'", table)
		return &view.Expr{Value: "(" + filter + ")"}, true
	}
	return nil, false
}

func GetMetricIDFilter(e *CHEngine) (view.Node, error) {
	table := e.Table
	metricID, ok := trans_prometheus.ORGPrometheus[e.ORGID].MetricNameToID[table]
	if !ok {
		errorMessage := fmt.Sprintf("%s not found", table)
		return nil, common.NewError(common.RESOURCE_NOT_FOUND, errorMessage)
	}
	filter := fmt.Sprintf("metric_id=%d", metricID)
	return &view.Expr{Value: "(" + filter + ")"}, nil
}
