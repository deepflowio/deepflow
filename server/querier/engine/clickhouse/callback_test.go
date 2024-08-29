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
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

func TestTimeFill(t *testing.T) {
	m := view.NewModel()
	m.Time.TimeStart = 1645089282
	m.Time.TimeEnd = 1645175682
	m.Time.Fill = "0"
	m.Time.Interval = 21600
	m.Time.Alias = "time"
	callback := TimeFill([]interface{}{m})
	columns := []interface{}{
		"time",
		"field_0",
		"field_1",
	}
	t1 := uint32(1645092000)
	t2 := uint32(1645113600)
	v1, v2, v3, v4 := 2, 3, 1, 4
	s1, s2 := "1", "0"
	values := []interface{}{
		[]interface{}{
			t1,
			s1,
			v1,
		},
		[]interface{}{
			t1,
			s2,
			v2,
		},
		[]interface{}{
			t2,
			s1,
			v3,
		},
		[]interface{}{
			t2,
			s2,
			v4,
		},
	}
	wt1 := uint32(1645070400)
	wt2 := uint32(1645135200)
	wt3 := uint32(1645156800)
	want := []interface{}{
		[]interface{}{
			wt1,
			s1,
			0,
		},
		[]interface{}{
			t1,
			s1,
			v1,
		},
		[]interface{}{
			t2,
			s1,
			v3,
		},
		[]interface{}{
			wt2,
			s1,
			0,
		},
		[]interface{}{
			wt3,
			s1,
			0,
		},
		[]interface{}{
			wt1,
			s2,
			0,
		},
		[]interface{}{
			t1,
			s2,
			v2,
		},
		[]interface{}{
			t2,
			s2,
			v4,
		},
		[]interface{}{
			wt2,
			s2,
			0,
		},
		[]interface{}{
			wt3,
			s2,
			0,
		},
	}
	result := &common.Result{
		Columns: columns,
		Values:  values,
		Schemas: common.ColumnSchemas{&common.ColumnSchema{
			Type:      common.COLUMN_SCHEMA_TYPE_TAG,
			ValueType: "UInt32",
		}, &common.ColumnSchema{
			Type:      common.COLUMN_SCHEMA_TYPE_TAG,
			ValueType: "String",
		}, &common.ColumnSchema{
			Type:      common.COLUMN_SCHEMA_TYPE_METRICS,
			ValueType: "Float64",
		},
		},
	}
	callback(result)
	if !reflect.DeepEqual(result.Values, want) {
		t.Errorf("Callback: TimeFill, columns: %v, values: %v, newValues: %v, want: %v", columns, values, result.Values, want)
	}
}
