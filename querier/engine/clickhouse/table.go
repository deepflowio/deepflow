package clickhouse

var TABLE_MAP = map[string][]string{
	"flow_log": []string{"l4_flow_log"},
}

func GetDatabases() map[string][]interface{} {
	var values []interface{}
	for db := range TABLE_MAP {
		values = append(values, []string{db})
	}
	return map[string][]interface{}{
		"columns": []interface{}{"name"},
		"values":  values,
	}
}

func GetTables(db string) map[string][]interface{} {
	var values []interface{}
	tables, ok := TABLE_MAP[db]
	if !ok {
		return nil
	}
	for _, table := range tables {
		values = append(values, []string{table})
	}
	return map[string][]interface{}{
		"columns": []interface{}{"name"},
		"values":  values,
	}
}
