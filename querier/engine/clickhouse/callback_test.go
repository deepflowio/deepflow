package clickhouse

import (
	//"github.com/k0kubun/pp"
	//"metaflow/querier/common"
	//"metaflow/querier/parse"
	//"metaflow/querier/querier"
	"metaflow/querier/engine/clickhouse/view"
	"reflect"
	"testing"
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
	values := []interface{}{
		[]interface{}{
			1645092000,
			1,
			2,
		},
	}
	want := []interface{}{
		[]interface{}{
			1645070400,
			0,
			0,
		},
		[]interface{}{
			1645092000,
			1,
			2,
		},
		[]interface{}{
			1645113600,
			0,
			0,
		},
		[]interface{}{
			1645135200,
			0,
			0,
		},
		[]interface{}{
			1645156800,
			0,
			0,
		},
	}
	newValues := callback(columns, values)
	if !reflect.DeepEqual(newValues, want) {
		t.Errorf("Callback: TimeFill, columns: %v, values: %v, newValues: %v, want: %v", columns, values, newValues, want)
	}
}
