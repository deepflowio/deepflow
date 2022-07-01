package clickhouse

import (
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/common"
)

func GetDatabases() map[string][]interface{} {
	var values []interface{}
	for db := range common.DB_TABLE_MAP {
		values = append(values, []string{db})
	}
	return map[string][]interface{}{
		"columns": []interface{}{"name"},
		"values":  values,
	}
}

func GetTables(db string) map[string][]interface{} {
	var values []interface{}
	tables, ok := common.DB_TABLE_MAP[db]
	if !ok {
		return nil
	}
	if db == "ext_metrics" {
		values = append(values, common.GetExtTables(db)...)
	} else {
		for _, table := range tables {
			values = append(values, []string{table})
		}
	}
	return map[string][]interface{}{
		"columns": []interface{}{"name"},
		"values":  values,
	}
}
