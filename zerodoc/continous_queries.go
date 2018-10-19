package zerodoc

import (
	"fmt"
	"reflect"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

func flatGetDBTagsInStruct(t reflect.Type) []string {
	ret := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		switch f.Type.Kind() {
		case reflect.Struct:
			ret = append(ret, flatGetDBTagsInStruct(f.Type)...)
		default:
			if v, ok := f.Tag.Lookup("db"); ok {
				ret = append(ret, v)
			}
		}
	}
	return ret
}

func getCQ(field string) string {
	if field == "sum_flow_count" {
		return "sum(sum_closed_flow_count)+last(sum_flow_count)-last(sum_closed_flow_count) AS sum_flow_count"
	}
	return fmt.Sprintf("%s(%s) AS %s", field[0:3], field, field)
}

func GetContinousQueryString(obj app.Meter) string {
	fields := flatGetDBTagsInStruct(reflect.TypeOf(obj).Elem())
	queries := make([]string, len(fields))
	for i, v := range fields {
		queries[i] = getCQ(v)
	}
	return strings.Join(queries, ", ")
}
